import pytest
from fastapi.testclient import TestClient

from cpbs.authority.client import AuthorityClient
from cpbs.authority.hsm import Authority
from cpbs.authority.service import create_app
from cpbs.clock import ManualClock
from cpbs.config import Config
from cpbs.crypto import seal
from cpbs.crypto.groupsig import GroupScheme
from cpbs.protocol.core import FIELD_SERIAL, encode_fields
from cpbs.protocol.session import SenderSession
from cpbs.protocol.verifier import Verifier


@pytest.fixture(params=["bbs04"])
def api(request):
    authority = Authority(request.param)
    client = AuthorityClient("", client=TestClient(create_app(authority)))
    return authority, client, GroupScheme(request.param)


def enrol(client, scheme, member_id):
    epoch, _, gpk = client.current()
    return epoch, gpk, client.enroll(scheme, member_id, epoch, gpk)


def session_for(client, scheme, member_id, clock, fields=None):
    epoch, gpk, memkey = enrol(client, scheme, member_id)
    c_enc = seal.seal(client.responder_pk(), encode_fields(fields or {}))
    return SenderSession(scheme, scheme.signing_keys(memkey, gpk), epoch, c_enc, clock.now())


def test_enrol_sign_open(api):
    authority, client, scheme = api
    clock = ManualClock()
    sessions = {m: session_for(client, scheme, m, clock) for m in ["SN-A", "SN-B", "SN-C"]}

    v = Verifier(scheme, Config(scheme=scheme.name), clock)
    epoch, _, gpk = client.current()
    v.set_group_key(epoch, gpk)
    for s in sessions.values():
        assert v.handle(s.heartbeat(clock.now())).status == "core_verified"

    res = client.open(sessions["SN-B"].core_bytes, requester="TR-1", ticket="INC-42")
    assert res["member_id"] == "SN-B"
    audit = client.audit()
    assert audit["valid"] and audit["entries"][-1]["ticket"] == "INC-42"


def test_responder_tier_decrypt(api):
    _, client, scheme = api
    s = session_for(client, scheme, "OP-1", ManualClock(),
                    {FIELD_SERIAL: b"1581F5FHC1234"})
    fields = client.decrypt(s.core.c_enc, requester="police", ticket="T1", session=s.session_id.hex())
    assert fields[FIELD_SERIAL] == b"1581F5FHC1234"
    assert client.audit()["entries"][-1]["action"] == "decrypt"


def test_revocation_by_epoch(api):
    authority, client, scheme = api
    clock = ManualClock()
    old = session_for(client, scheme, "SN-BAD", clock)
    client.revoke("SN-BAD")
    client.rollover()
    with pytest.raises(PermissionError):
        enrol(client, scheme, "SN-BAD")
    good = session_for(client, scheme, "SN-GOOD", clock)

    v = Verifier(scheme, Config(scheme=scheme.name), clock)
    epoch, _, gpk = client.current()
    v.set_group_key(epoch, gpk)
    assert v.handle(old.heartbeat(clock.now())).status == "wrong_epoch"
    assert v.handle(good.heartbeat(clock.now())).status == "core_verified"


def test_audit_tamper_detected(api):
    authority, client, scheme = api
    s = session_for(client, scheme, "SN-A", ManualClock())
    client.open(s.core_bytes, "TR", "1")
    client.open(s.core_bytes, "TR", "2")
    authority.audit.entries[0]["ticket"] = "forged"
    assert not authority.audit.verify()


def test_open_rejects_garbage(api):
    _, client, _ = api
    with pytest.raises(PermissionError):
        client.open(b"\x01\x01" + bytes(60), "TR", "x")
