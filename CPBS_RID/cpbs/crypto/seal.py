"""Encrypted field blob C_enc: libsodium sealed box (X25519 + XSalsa20-Poly1305).

Anonymous public-key encryption: a fresh ephemeral key per ciphertext keeps
ciphertexts unlinkable across sessions. Overhead: 32 B ephemeral key + 16 B tag.
"""
from typing import Optional

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, PublicKey, SealedBox

OVERHEAD = 48


def generate_keypair() -> tuple[bytes, bytes]:
    sk = PrivateKey.generate()
    return bytes(sk), bytes(sk.public_key)


def seal(pk: bytes, plaintext: bytes) -> bytes:
    return SealedBox(PublicKey(pk)).encrypt(plaintext)


def unseal(sk: bytes, ciphertext: bytes) -> Optional[bytes]:
    try:
        return SealedBox(PrivateKey(sk)).decrypt(ciphertext)
    except CryptoError:
        return None
