"""Group signatures via IBM libgroupsig (C, MCL, BLS12-381), scheme BBS04.

BBS04 is used because its opening decrypts the signer identity (near-constant
time); PS16 and KLAP20 open by testing every member (linear in group size).

Calls the libgroupsig C API through the cffi module built by pygroupsig, but
manages native memory itself: pygroupsig's sign/verify never free their
message objects, which leaks on every call and would distort long benchmarks.

Keys, signatures and join messages cross process boundaries as raw bytes
(libgroupsig's own export format).
"""
from dataclasses import dataclass
from typing import Optional, Tuple

from _groupsig import ffi, lib

SCHEMES = {"bbs04": lib.GROUPSIG_BBS04_CODE}

_initialised = set()


def _init(code: int) -> None:
    # The seed only feeds libgroupsig's fallback PRNG; with HAVE_GETRANDOM
    # (set on Linux) randomness comes from getrandom() and MCL's CSPRNG.
    if code not in _initialised:
        if lib.groupsig_init(code, 0) != lib.IOK:
            raise RuntimeError("groupsig_init failed")
        _initialised.add(code)


def _check(rc: int, what: str) -> None:
    if rc == lib.IERROR:
        raise RuntimeError(f"libgroupsig: {what} failed")


def _export(fn, obj) -> bytes:
    buf = ffi.new("byte_t **")
    size = ffi.new("uint32_t *")
    _check(fn(buf, size, obj), "export")
    out = bytes(ffi.buffer(buf[0], size[0]))
    lib.free(buf[0])
    return out


def _owned(ptr, free, what: str):
    """Attach a destructor to a native object; raise on NULL (e.g. malformed import)."""
    if ptr == ffi.NULL:
        raise ValueError(f"malformed {what}")
    return ffi.gc(ptr, free)


def _message(data: bytes):
    return ffi.gc(lib.message_from_bytes(data, len(data)), lib.message_free)


class GroupScheme:
    """One libgroupsig scheme; all keys and signatures are handled as bytes."""

    def __init__(self, name: str):
        self.name = name
        self.code = SCHEMES[name]
        _init(self.code)

    # -- (de)serialisation helpers -----------------------------------------

    def _grpkey(self, b: bytes):
        return _owned(lib.groupsig_grp_key_import(self.code, b, len(b)), lib.groupsig_grp_key_free, "group key")

    def _memkey(self, b: bytes):
        return _owned(lib.groupsig_mem_key_import(self.code, b, len(b)), lib.groupsig_mem_key_free, "member key")

    def _sig(self, b: bytes):
        return _owned(lib.groupsig_signature_import(self.code, b, len(b)), lib.groupsig_signature_free,
                      "group signature")

    # -- group manager -------------------------------------------------------

    def setup(self) -> "GroupState":
        grpkey = lib.groupsig_grp_key_init(self.code)
        mgrkey = lib.groupsig_mgr_key_init(self.code)
        gml = lib.gml_init(self.code)
        _check(lib.groupsig_setup(self.code, grpkey, mgrkey, gml), "setup")
        return GroupState(
            grpkey=_export(lib.groupsig_grp_key_export, grpkey),
            native_grpkey=ffi.gc(grpkey, lib.groupsig_grp_key_free),
            native_mgrkey=ffi.gc(mgrkey, lib.groupsig_mgr_key_free),
            native_gml=ffi.gc(gml, lib.gml_free),
        )

    def join_steps(self) -> Tuple[int, int]:
        """(first step, last step); even/odd steps alternate between manager and member."""
        start, seq = ffi.new("uint8_t *"), ffi.new("uint8_t *")
        _check(lib.groupsig_get_joinstart(self.code, start), "get_joinstart")
        _check(lib.groupsig_get_joinseq(self.code, seq), "get_joinseq")
        return start[0], seq[0]

    def is_manager_step(self, step: int) -> bool:
        start, _ = self.join_steps()
        return (step % 2 == 0) == (start == 0)

    def join_mgr(self, state: "GroupState", step: int, msg_in: Optional[bytes]) -> bytes:
        """Run one manager step (may add a GML entry); returns the outgoing message."""
        mout = ffi.new("message_t **")
        min_ = _message(msg_in) if msg_in is not None else ffi.NULL
        _check(lib.groupsig_join_mgr(mout, state.native_gml, state.native_mgrkey, step, min_,
                                     state.native_grpkey), "join_mgr")
        return _take_message(mout[0])

    def join_mem(self, grpkey_b: bytes, step: int, msg_in: Optional[bytes],
                 memkey_b: Optional[bytes]) -> Tuple[Optional[bytes], bytes]:
        """Run one member step; returns (outgoing message or None, member key bytes)."""
        grpkey = self._grpkey(grpkey_b)
        memkey = self._memkey(memkey_b) if memkey_b else ffi.gc(
            lib.groupsig_mem_key_init(self.code), lib.groupsig_mem_key_free)
        mout = ffi.new("message_t **")
        min_ = _message(msg_in) if msg_in is not None else ffi.NULL
        _check(lib.groupsig_join_mem(mout, memkey, step, min_, grpkey), "join_mem")
        out = _take_message(mout[0]) if mout[0] != ffi.NULL else None
        return out, _export(lib.groupsig_mem_key_export, memkey)

    # -- signing / verification / opening -----------------------------------

    def sign(self, memkey_b: bytes, grpkey_b: bytes, msg: bytes, *, keys=None) -> bytes:
        memkey, grpkey = keys or (self._memkey(memkey_b), self._grpkey(grpkey_b))
        sig = ffi.gc(lib.groupsig_signature_init(self.code), lib.groupsig_signature_free)
        _check(lib.groupsig_sign(sig, _message(msg), memkey, grpkey, 0), "sign")
        return _export(lib.groupsig_signature_export, sig)

    def verify(self, sig_b: bytes, msg: bytes, grpkey_b: bytes, *, grpkey=None) -> bool:
        try:
            sig = self._sig(sig_b)
        except ValueError:  # undecodable bytes are simply an invalid signature
            return False
        ok = ffi.new("uint8_t *")
        _check(lib.groupsig_verify(ok, sig, _message(msg), grpkey or self._grpkey(grpkey_b)), "verify")
        return ok[0] == 1

    def open(self, sig_b: bytes, state: "GroupState") -> int:
        """Return the signer's member index in the GML (BBS04 openings carry no proof)."""
        index = ffi.new("uint64_t *")
        proof = ffi.gc(lib.groupsig_proof_init(self.code), lib.groupsig_proof_free)
        _check(lib.groupsig_open(index, proof, ffi.NULL, self._sig(sig_b), state.native_grpkey,
                                 state.native_mgrkey, state.native_gml), "open")
        return index[0]

    # Pre-imported keys for hot loops (avoids re-importing on every call).
    def signing_keys(self, memkey_b: bytes, grpkey_b: bytes):
        return self._memkey(memkey_b), self._grpkey(grpkey_b)

    def verifying_key(self, grpkey_b: bytes):
        return self._grpkey(grpkey_b)


def _take_message(msg) -> bytes:
    out = bytes(ffi.buffer(msg.bytes, msg.length))
    lib.message_free(msg)
    return out


@dataclass
class GroupState:
    """Group manager state for one group (one epoch).

    Manager key and GML stay native and in memory: this is the simulated HSM
    content, and libgroupsig cannot re-import a non-empty BBS04 GML anyway.
    """
    grpkey: bytes  # public, distributed to receivers
    native_grpkey: object
    native_mgrkey: object
    native_gml: object


def join_local(scheme: GroupScheme, state: GroupState) -> bytes:
    """Run the full join protocol in-process; returns the member key (tests, benchmarks)."""
    first, last = scheme.join_steps()
    msg, memkey = None, None
    for step in range(first, last + 1):
        if scheme.is_manager_step(step):
            msg = scheme.join_mgr(state, step, msg)
        else:
            msg, memkey = scheme.join_mem(state.grpkey, step, msg, memkey)
    return memkey
