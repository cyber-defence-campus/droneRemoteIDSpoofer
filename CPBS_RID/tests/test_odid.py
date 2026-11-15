import os

import pytest

from cpbs.odid import messages as m
from cpbs.odid.parser import parse_astm_payload

T = 1_780_000_000.0  # fixed unix time


def test_message_sizes():
    for msg in [m.build_basic_id(b"SN123"),
                m.build_basic_id_session(0xE1, bytes(19)),
                m.build_location_vector(473_766_000, 85_417_000, 90, T),
                m.build_system(473_760_000, 85_410_000, T),
                m.build_operator_id("CHEabc")]:
        assert len(msg) == 25


def test_session_basic_id_roundtrip():
    sid = os.urandom(19)
    msg = m.build_basic_id_session(0xE1, sid)
    sid_type, raw = m.parse_basic_id_session(msg)
    assert sid_type == 0xE1 and raw[:19] == sid
    decoded = parse_astm_payload(msg)[0][0]
    assert decoded["id_type"] == 4 and decoded["session_id_type"] == 0xE1


@pytest.mark.parametrize("length", [0, 1, 17, 18, 40, 63, 64, 86, 178, 255])
def test_auth_pages_roundtrip(length):
    data = os.urandom(length)
    pages = m.build_auth_pages(m.AUTH_TYPE_SAM, data, 12345)
    assert len(pages) == m.auth_pages_needed(length)
    assert m.auth_capacity(len(pages)) >= length
    assert m.reassemble_auth(list(reversed(pages))) == (m.AUTH_TYPE_SAM, 12345, data)


def test_auth_too_long():
    with pytest.raises(ValueError):
        m.build_auth_pages(m.AUTH_TYPE_SAM, bytes(256), 0)


def test_auth_missing_page():
    pages = m.build_auth_pages(m.AUTH_TYPE_SAM, os.urandom(60), 0)
    assert m.reassemble_auth(pages[:-1]) is None


def test_pack_roundtrip_and_reference_parser():
    msgs = [m.build_basic_id_session(0xE1, os.urandom(19)),
            m.build_location_vector(473_766_000, 85_417_000, 270, T, speed=5.0, height=50.0),
            m.build_system(473_760_000, 85_410_000, T)]
    msgs += m.build_auth_pages(m.AUTH_TYPE_SAM, os.urandom(70), m.odid_timestamp(T))
    pack = m.build_message_pack(msgs)
    assert len(pack) == 3 + 25 * len(msgs)
    assert m.parse_message_pack(pack) == msgs

    decoded, _ = parse_astm_payload(pack)
    assert [d["msg_type"] for d in decoded] == [0, 1, 4, 2, 2, 2, 2]
    loc = decoded[1]
    assert abs(loc["lat"] - 47.3766) < 1e-6 and loc["speed_mps"] == 5.0
    assert decoded[3]["auth_type"] == m.AUTH_TYPE_SAM
    assert decoded[3]["auth_timestamp_epoch"] == int(T)


def test_pack_limits():
    with pytest.raises(ValueError):
        m.build_message_pack([m.build_operator_id()] * 10)
    assert m.parse_message_pack(b"\xf2\x19\x02" + bytes(25)) is None  # truncated
