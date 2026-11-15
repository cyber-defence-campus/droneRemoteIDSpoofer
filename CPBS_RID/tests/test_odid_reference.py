"""Cross-check CPBS message packs against the opendroneid-core-c reference decoder.

Build the checker first (skipped otherwise):
  gcc -O2 -I../opendroneid-core-c/libopendroneid -o bench/odid_refcheck \
      bench/odid_refcheck.c ../opendroneid-core-c/libopendroneid/opendroneid.c -lm
"""
import os
import subprocess
from pathlib import Path

import pytest

from cpbs.odid import messages as m

CHECKER = Path(__file__).parent.parent / "bench" / "odid_refcheck"
pytestmark = pytest.mark.skipif(not CHECKER.exists(), reason="reference checker not built")

T = 1_780_000_000.0


def decode(pack: bytes) -> dict:
    out = subprocess.run([str(CHECKER), pack.hex()], capture_output=True, text=True, check=True).stdout
    fields, auth = {}, []
    for line in out.splitlines():
        parts = line.split()
        if parts[0] == "auth_page":
            auth.append(dict(zip(parts[0::2], parts[1::2])))
        else:
            fields[parts[0]] = parts[1]
    fields["auth"] = auth
    return fields


@pytest.mark.parametrize("auth_len", [70, 178])
def test_reference_decoder_agrees(auth_len):
    sid = os.urandom(19)
    data = os.urandom(auth_len)
    msgs = [m.build_basic_id_session(0xE1, sid),
            m.build_location_vector(473_766_000, 85_417_000, 270, T, speed=5.0, height=50.0),
            m.build_system(473_760_000, 85_410_000, T)]
    msgs += m.build_auth_pages(m.AUTH_TYPE_SAM, data, m.odid_timestamp(T))
    msgs = msgs[:m.PACK_MAX_MESSAGES] if len(msgs) <= 9 else [msgs[0]] + msgs[3:]
    d = decode(m.build_message_pack(msgs))

    assert d["rc"] == "0"
    assert d["basic_id_type"] == "4"
    assert bytes.fromhex(d["basic_id"])[:20] == bytes([0xE1]) + sid
    if "lat" in d:
        assert abs(float(d["lat"]) - 47.3766) < 1e-6 and float(d["speed"]) == 5.0
        assert float(d["loc_ts"]) == round(T % 3600, 1)
    p0 = d["auth"][0]
    assert p0["type"] == "5" and int(p0["length"]) == auth_len and int(p0["ts"]) == m.odid_timestamp(T)
    blob = b"".join(bytes.fromhex(p["data"]) for p in sorted(d["auth"], key=lambda p: int(p["auth_page"])))
    assert blob[:auth_len] == data
