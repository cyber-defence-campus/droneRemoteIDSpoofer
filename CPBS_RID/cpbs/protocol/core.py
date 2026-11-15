"""Session Core: binds an ephemeral session key to an anonymous group membership.

    Core = version | scheme | epoch | pk_sess | len | C_enc | len | GroupSig
    GroupSig = GroupSign_GSK(DOMAIN || version | scheme | epoch | pk_sess | len | C_enc)

SessionID is not carried in the Core: it is SHA-256(pk_sess)[:19] and is sent
in the Basic ID of every pack, so receivers derive and compare it.
"""
import struct
from dataclasses import dataclass
from typing import Optional

from cpbs.crypto.groupsig import SCHEMES, GroupScheme
from cpbs.crypto.session import PK_LEN, session_id

VERSION = 1
DOMAIN = b"CPBS-CORE-v1"
SCHEME_IDS = {"bbs04": 2}  # 1 was PS16 (dropped: linear-time opening)
SCHEME_NAMES = {v: k for k, v in SCHEME_IDS.items()}
_HDR = struct.Struct("<BBI")  # version, scheme, epoch


@dataclass
class Core:
    scheme: str
    epoch: int
    pk: bytes
    c_enc: bytes
    group_sig: bytes

    @property
    def session_id(self) -> bytes:
        return session_id(self.pk)

    def signed_part(self) -> bytes:
        return (_HDR.pack(VERSION, SCHEME_IDS[self.scheme], self.epoch) + self.pk
                + bytes([len(self.c_enc)]) + self.c_enc)

    def encode(self) -> bytes:
        return self.signed_part() + struct.pack("<H", len(self.group_sig)) + self.group_sig

    @classmethod
    def decode(cls, data: bytes) -> Optional["Core"]:
        try:
            version, scheme_id, epoch = _HDR.unpack_from(data, 0)
            if version != VERSION or scheme_id not in SCHEME_NAMES:
                return None
            off = _HDR.size
            pk = data[off:off + PK_LEN]
            off += PK_LEN
            n = data[off]
            c_enc = data[off + 1:off + 1 + n]
            off += 1 + n
            (m,) = struct.unpack_from("<H", data, off)
            sig = data[off + 2:off + 2 + m]
            if len(pk) != PK_LEN or len(c_enc) != n or len(sig) != m or off + 2 + m != len(data):
                return None
            return cls(SCHEME_NAMES[scheme_id], epoch, pk, c_enc, sig)
        except (struct.error, IndexError):
            return None


def build_core(scheme: GroupScheme, signing_keys, epoch: int, pk: bytes, c_enc: bytes) -> Core:
    """Group-sign a new session (the expensive step, done once per session)."""
    if len(c_enc) > 255:
        raise ValueError("C_enc too long")
    core = Core(scheme.name, epoch, pk, c_enc, b"")
    core.group_sig = scheme.sign(None, None, DOMAIN + core.signed_part(), keys=signing_keys)
    return core


def verify_core(scheme: GroupScheme, grpkey, core: Core) -> bool:
    """Membership check: valid group signature under the epoch's group public key."""
    if core.scheme != scheme.name:
        return False
    return scheme.verify(core.group_sig, DOMAIN + core.signed_part(), None, grpkey=grpkey)


# --- C_enc plaintext: small TLV, zero-padded to a fixed length -------------
# No operator ID: opening sigma_G already yields the registered identity.

FIELD_SERIAL = 2             # ANSI/CTA-2063-A, at most 20 chars
FIELD_OPERATOR_LOCATION = 3  # exact lat/lon (1e-7 deg), optional

# serial TLV (2 + 20) + location TLV (2 + 8); padding hides which fields are
# present and the serial length, which would otherwise link sessions
FIELDS_LEN = 32


def encode_fields(fields: dict) -> bytes:
    out = b""
    for tag, value in fields.items():
        out += bytes([tag, len(value)]) + value
    if len(out) > FIELDS_LEN:
        raise ValueError("C_enc fields too long")
    return out.ljust(FIELDS_LEN, b"\x00")


def decode_fields(data: bytes) -> dict:
    fields, i = {}, 0
    while i + 2 <= len(data):
        tag, n = data[i], data[i + 1]
        if tag == 0:  # padding
            break
        fields[tag] = data[i + 2:i + 2 + n]
        i += 2 + n
    return fields


assert set(SCHEME_IDS) == set(SCHEMES)
