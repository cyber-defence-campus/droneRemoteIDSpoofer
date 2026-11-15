import pytest

from cpbs.clock import ManualClock
from cpbs.config import Config
from cpbs.crypto import seal
from cpbs.crypto import session as sess
from cpbs.crypto.groupsig import GroupScheme, join_local
from cpbs.odid import messages as odid
from cpbs.protocol import framing
from cpbs.protocol.core import (FIELD_SERIAL, FIELDS_LEN, Core, decode_fields, encode_fields)
from cpbs.protocol.session import SenderSession
from cpbs.protocol.verifier import Verifier

EPOCH = 7


@pytest.fixture(scope="module", params=["bbs04"])
def group(request):
    scheme = GroupScheme(request.param)
    state = scheme.setup()
    memkeys = [join_local(scheme, state) for _ in range(3)]
    return scheme, state, memkeys


@pytest.fixture
def env(group):
    scheme, state, memkeys = group
    clock = ManualClock()
    cfg = Config(scheme=scheme.name)
    v = Verifier(scheme, cfg, clock)
    v.set_group_key(EPOCH, state.grpkey)
    resp_sk, resp_pk = seal.generate_keypair()

    def new_session(member=1, epoch=EPOCH, grpkey=None):
        keys = scheme.signing_keys(memkeys[member], grpkey or state.grpkey)
        # sealed freshly per session: reusing a ciphertext would link sessions
        c_enc = seal.seal(resp_pk, encode_fields({FIELD_SERIAL: b"1581F5FHC1234"}))
        return SenderSession(scheme, keys, epoch, c_enc, clock.now())

    return scheme, state, clock, v, new_session, resp_sk


def data(s, clock, lat=473_766_000):
    return s.data_pack(odid.build_location_vector(lat, 85_417_000, 90, clock.now()),
                       odid.build_system(473_760_000, 85_410_000, clock.now()), clock.now())


def statuses(v, packs):
    return [v.handle(p).status for p in packs]


def hb(v, s, clock):
    return v.handle(s.heartbeat(clock.now())).status


def test_core_roundtrip_and_sizes(env):
    scheme, state, clock, v, new_session, _ = env
    s = new_session()
    assert Core.decode(s.core_bytes) == s.core
    assert Core.decode(s.core_bytes[:-1]) is None
    assert len(data(s, clock)) == 3 + 7 * 25
    assert len(s.heartbeat(clock.now())) == 4 + 1 + sess.SESSION_ID_LEN + 4 + 2 + len(s.core_bytes) + 64
    assert framing.parse_heartbeat(s.heartbeat(clock.now())[:-1]) is None


def test_late_joiner_flow(env):
    _, _, clock, v, new_session, _ = env
    s = new_session()
    assert v.handle(data(s, clock)).status == "unknown_session"
    assert hb(v, s, clock) == "core_verified"
    assert v.handle(data(s, clock)).status == "verified"
    assert hb(v, s, clock) == "verified"  # cached: Wrapper check only, no GroupVerify


def test_tampering_rejected(env):
    _, _, clock, v, new_session, _ = env
    s = new_session()
    hb(v, s, clock)
    pack = bytearray(data(s, clock))
    pack[3 + 25 + 6] ^= 1  # latitude byte of the Location message
    assert v.handle(bytes(pack)).status == "bad_sig"


def test_tampered_core_rejected(env):
    _, _, clock, v, new_session, _ = env
    s = new_session()
    core = bytearray(s.core_bytes)
    core[-5] ^= 1  # inside the group signature
    frame = framing.build_heartbeat(s.key, bytes(core), odid.odid_timestamp(clock.now()))
    assert v.handle(frame).status == "core_rejected"


def test_stale_and_replay(env):
    _, _, clock, v, new_session, _ = env
    s = new_session()
    hb(v, s, clock)
    p = data(s, clock)
    assert v.handle(p).status == "verified"
    assert v.handle(p).status == "replay"
    old, old_hb = data(s, clock), s.heartbeat(clock.now())
    clock.advance(3.0)
    assert v.handle(old).status == "stale"
    assert v.handle(old_hb).status == "stale"


def test_wrong_epoch(env):
    _, _, clock, v, new_session, _ = env
    old, new = new_session(epoch=EPOCH - 1), new_session(epoch=EPOCH + 1)
    assert hb(v, old, clock) == "wrong_epoch"
    assert hb(v, new, clock) == "future_epoch"


def test_session_id_hijack(env):
    """Another key re-broadcasting a victim's Core: SessionID != H(pk) -> rejected."""
    _, _, clock, v, new_session, _ = env
    victim, attacker = new_session(member=0), new_session(member=2)
    frame = framing.build_heartbeat(attacker.key, victim.core_bytes, odid.odid_timestamp(clock.now()))
    assert v.handle(frame).status == "core_rejected"


def test_non_member_rejected(env, group):
    scheme, _, clock, v, _, _ = env
    other = scheme.setup()
    outsider_key = join_local(scheme, other)
    keys = scheme.signing_keys(outsider_key, other.grpkey)
    s = SenderSession(scheme, keys, EPOCH, b"", clock.now())
    assert hb(v, s, clock) == "core_rejected"


def test_rate_limit(env):
    _, _, clock, v, new_session, _ = env
    v.bucket.rate = v.bucket.tokens = 1
    a, b = new_session(), new_session()
    assert hb(v, a, clock) == "core_verified"
    assert hb(v, b, clock) == "rate_limited"
    clock.advance(1.0)
    assert hb(v, b, clock) == "core_verified"


def test_open_and_c_enc(env, group):
    scheme, state, clock, v, new_session, resp_sk = env
    s = new_session(member=2)
    assert scheme.open(s.core.group_sig, state) == 2
    assert decode_fields(seal.unseal(resp_sk, s.core.c_enc))[FIELD_SERIAL] == b"1581F5FHC1234"


def test_sessions_unlinkable_bytes(env):
    _, _, _, _, new_session, _ = env
    a, b = new_session(member=1), new_session(member=1)
    assert a.session_id != b.session_id and a.core.c_enc != b.core.c_enc
    assert a.core.group_sig != b.core.group_sig


def test_fields_padded_to_fixed_length():
    short, long = encode_fields({FIELD_SERIAL: b"SN1"}), encode_fields({FIELD_SERIAL: b"X" * 20})
    assert len(short) == len(long) == FIELDS_LEN
    assert decode_fields(short) == {FIELD_SERIAL: b"SN1"}
    with pytest.raises(ValueError):
        encode_fields({FIELD_SERIAL: b"X" * FIELDS_LEN})
