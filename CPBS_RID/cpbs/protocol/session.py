"""Sender side: one CPBS session (ephemeral key, Core, sequence numbers)."""
from cpbs.crypto.groupsig import GroupScheme
from cpbs.crypto.session import SessionKey
from cpbs.metrics import NULL, Metrics
from cpbs.odid import messages as odid
from cpbs.protocol import framing
from cpbs.protocol.core import build_core


class SenderSession:
    def __init__(self, scheme: GroupScheme, signing_keys, epoch: int, c_enc: bytes,
                 started: float, metrics: Metrics = NULL):
        self.metrics = metrics
        with metrics.timer("session_keygen"):
            self.key = SessionKey()
        with metrics.timer("group_sign", scheme=scheme.name):
            self.core = build_core(scheme, signing_keys, epoch, self.key.pk, c_enc)
        self.core_bytes = self.core.encode()
        self.epoch = epoch
        self.started = started
        self.seq = 0
        metrics.event("session_start", session=self.key.session_id.hex(), epoch=epoch,
                      core_bytes=len(self.core_bytes), group_sig_bytes=len(self.core.group_sig),
                      c_enc_bytes=len(c_enc))

    @property
    def session_id(self) -> bytes:
        return self.key.session_id

    def data_pack(self, location: bytes, system: bytes, now: float) -> bytes:
        with self.metrics.timer("pack_sign", kind="data"):
            pack = framing.build_pack(self.key, self.seq, framing.KIND_DATA, b"",
                                      [location, system], odid.odid_timestamp(now))
        self.seq += 1
        return pack

    def heartbeat(self, now: float) -> bytes:
        """One heartbeat frame: the Core plus a fresh Wrapper signature."""
        with self.metrics.timer("pack_sign", kind="heartbeat"):
            return framing.build_heartbeat(self.key, self.core_bytes, odid.odid_timestamp(now))
