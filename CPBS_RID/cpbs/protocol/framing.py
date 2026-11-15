"""CPBS framing: standard ASTM F3411 data packs + a separate heartbeat frame.

Data pack (F3411 message pack, parsed by existing receivers): the session's
Basic ID (UA ID type 4, Specific Session ID), Location, System and exactly one
Authentication message (Auth type 5, SAM) whose data is

    SAM type (1) | kind (1) | SeqNo (u16) | Ed25519 signature (64)

The signature covers DOMAIN | Auth timestamp (u32) | auth data before the
signature | all non-Auth messages of the pack (Basic ID included, so the pack
is bound to its SessionID). Only one Authentication message per pack: pages
are numbered per message, so two in one pack would collide.

Heartbeat frame (CPBS-specific, not an F3411 message, so legacy receivers
ignore it): carries the whole Core in one transmission plus the Wrapper,

    MAGIC (4) | version (1) | SessionID (19) | Timestamp (u32) | len (u16) | Core | sig (64)
    sig = Sign_sk_sess(HB_DOMAIN | SessionID | Timestamp | Core)

On air: one chained BLE extended advertisement (up to 1650 B), or several
vendor-specific IEs (up to 255 B each) in one Wi-Fi beacon / NAN frame.
"""
import struct
from dataclasses import dataclass
from typing import List, Optional

from cpbs.crypto import session as sess
from cpbs.odid import messages as odid

# Placeholder values from the experimental range; a deployment would need ICAO-assigned ones.
SAM_TYPE = 0xE1          # 225-255: private experimental range (F3411 Auth type 5)
SESSION_ID_TYPE = 0xE1   # 225-255: private experimental range (F3411 UA ID type 4)

KIND_DATA = 0x01
KIND_HEARTBEAT = 0x02

DOMAIN = b"CPBS-PACK-v1"
_AUTH_HDR = struct.Struct("<BBH")  # SAM type, kind, SeqNo

HB_MAGIC = b"CPBS"
HB_VERSION = 1
HB_DOMAIN = b"CPBS-HB-v1"
_HB_HDR = struct.Struct("<4sB19sIH")  # magic, version, SessionID, timestamp, Core length


@dataclass
class ParsedPack:
    session_id: bytes
    messages: List[bytes]        # non-Auth messages, in pack order
    auth_ts: int                 # Auth page-0 timestamp (seconds since 2019)
    kind: int
    seq: int
    body: bytes                  # kind-specific bytes
    sig: bytes
    signed_bytes: bytes

    def verify(self, pk: bytes) -> bool:
        return sess.verify(pk, self.signed_bytes, self.sig)

    def message(self, t: int) -> Optional[bytes]:
        return next((m for m in self.messages if odid.msg_type(m) == t), None)


def _signed_bytes(odid_ts: int, auth_prefix: bytes, others: List[bytes]) -> bytes:
    return DOMAIN + struct.pack("<I", odid_ts) + auth_prefix + b"".join(others)


def build_pack(key: sess.SessionKey, seq: int, kind: int, body: bytes,
               others: List[bytes], odid_ts: int) -> bytes:
    """Sign and assemble one pack; `others` excludes the Basic ID (added here)."""
    others = [odid.build_basic_id_session(SESSION_ID_TYPE, key.session_id)] + others
    prefix = _AUTH_HDR.pack(SAM_TYPE, kind, seq & 0xFFFF) + body
    sig = key.sign(_signed_bytes(odid_ts, prefix, others))
    auth = odid.build_auth_pages(odid.AUTH_TYPE_SAM, prefix + sig, odid_ts)
    return odid.build_message_pack(others + auth)


def build_heartbeat(key: sess.SessionKey, core: bytes, odid_ts: int) -> bytes:
    sig = key.sign(HB_DOMAIN + key.session_id + struct.pack("<I", odid_ts) + core)
    return _HB_HDR.pack(HB_MAGIC, HB_VERSION, key.session_id, odid_ts, len(core)) + core + sig


@dataclass
class ParsedHeartbeat:
    session_id: bytes
    auth_ts: int                 # seconds since 2019, same encoding as the Auth timestamp
    core: bytes
    sig: bytes
    kind: int = KIND_HEARTBEAT

    def verify(self, pk: bytes) -> bool:
        """The Wrapper check: the session key holder re-asserts this Core at auth_ts."""
        signed = HB_DOMAIN + self.session_id + struct.pack("<I", self.auth_ts) + self.core
        return sess.verify(pk, signed, self.sig)


def is_heartbeat(raw: bytes) -> bool:
    return raw[:4] == HB_MAGIC


def parse_heartbeat(raw: bytes) -> Optional[ParsedHeartbeat]:
    if len(raw) < _HB_HDR.size + sess.SIG_LEN:
        return None
    magic, version, sid, ts, n = _HB_HDR.unpack_from(raw)
    if magic != HB_MAGIC or version != HB_VERSION or len(raw) != _HB_HDR.size + n + sess.SIG_LEN:
        return None
    core = raw[_HB_HDR.size:_HB_HDR.size + n]
    return ParsedHeartbeat(session_id=sid, auth_ts=ts, core=core, sig=raw[-sess.SIG_LEN:])


def parse_pack(raw: bytes) -> Optional[ParsedPack]:
    msgs = odid.parse_message_pack(raw)
    if not msgs:
        return None
    others = [m for m in msgs if odid.msg_type(m) != odid.MsgType.AUTH]
    auth = odid.reassemble_auth([m for m in msgs if odid.msg_type(m) == odid.MsgType.AUTH])
    sid = odid.parse_basic_id_session(others[0]) if others else None
    if auth is None or sid is None or sid[0] != SESSION_ID_TYPE:
        return None
    auth_type, ts, data = auth
    if auth_type != odid.AUTH_TYPE_SAM or len(data) < _AUTH_HDR.size + sess.SIG_LEN:
        return None
    sam, kind, seq = _AUTH_HDR.unpack_from(data)
    if sam != SAM_TYPE:
        return None
    prefix, sig = data[:-sess.SIG_LEN], data[-sess.SIG_LEN:]
    return ParsedPack(session_id=sid[1][:sess.SESSION_ID_LEN], messages=others, auth_ts=ts,
                      kind=kind, seq=seq, body=prefix[_AUTH_HDR.size:], sig=sig,
                      signed_bytes=_signed_bytes(ts, prefix, others))

