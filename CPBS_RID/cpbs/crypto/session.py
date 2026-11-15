"""Session layer: ephemeral Ed25519 keys (libsodium via PyNaCl)."""
import hashlib

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

SESSION_ID_LEN = 19  # fills the type-4 UAS ID field (20 B minus the session-ID type byte)
SIG_LEN = 64
PK_LEN = 32


def session_id(pk: bytes) -> bytes:
    """SessionID = SHA-256(pk_sess) truncated; binds the identifier to the session key."""
    return hashlib.sha256(pk).digest()[:SESSION_ID_LEN]


class SessionKey:
    def __init__(self):
        self._sk = SigningKey.generate()
        self.pk = bytes(self._sk.verify_key)
        self.session_id = session_id(self.pk)

    def sign(self, msg: bytes) -> bytes:
        return self._sk.sign(msg).signature


def verify(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        VerifyKey(pk).verify(msg, sig)
        return True
    except (BadSignatureError, ValueError):
        return False
