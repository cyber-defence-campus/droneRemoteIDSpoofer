"""Receiver side: tiered verification of CPBS data packs and heartbeats (no I/O).

Cheapest checks first:
  data pack:  parse -> freshness (Δ) -> known session? -> SeqNo -> Ed25519
              (packs of sessions without a verified Core are dropped)
  heartbeat:  parse -> freshness (Δ) -> known session? Ed25519 Wrapper only
              new session: SessionID == H(pk) -> Ed25519 Wrapper -> epoch known
              (else wrong_epoch / future_epoch) -> rate limit
              -> GroupVerify (expensive) -> cache session
"""
import time
from dataclasses import dataclass
from typing import Dict, Optional, Union

from cpbs.clock import Clock
from cpbs.config import Config
from cpbs.crypto.groupsig import GroupScheme
from cpbs.metrics import NULL, Metrics
from cpbs.odid import messages as odid
from cpbs.protocol import framing
from cpbs.protocol.core import Core, verify_core


@dataclass
class Session:
    core: Core
    last_seq: int
    verified_at: float


@dataclass
class Result:
    status: str
    session_id: Optional[bytes] = None
    pack: Optional[Union[framing.ParsedPack, framing.ParsedHeartbeat]] = None
    session: Optional[Session] = None


class TokenBucket:
    def __init__(self, rate: float, clock: Clock):
        self.rate, self.clock = rate, clock
        self.tokens, self.t = rate, clock.now()

    def take(self) -> bool:
        now = self.clock.now()
        self.tokens = min(self.rate, self.tokens + (now - self.t) * self.rate)
        self.t = now
        if self.tokens >= 1:
            self.tokens -= 1
            return True
        return False


class Verifier:
    def __init__(self, scheme: GroupScheme, cfg: Config, clock: Clock, metrics: Metrics = NULL):
        self.scheme, self.cfg, self.clock, self.metrics = scheme, cfg, clock, metrics
        self.group_keys: Dict[int, object] = {}   # epoch -> native group public key
        self.sessions: Dict[bytes, Session] = {}
        self.bucket = TokenBucket(cfg.max_new_sessions_per_s, clock)

    def set_group_key(self, epoch: int, grpkey: bytes, keep_previous: bool = False) -> None:
        """Accept Cores of `epoch` only (and drop sessions of other epochs)."""
        native = self.scheme.verifying_key(grpkey)
        self.group_keys = {**(self.group_keys if keep_previous else {}), epoch: native}
        self.sessions = {k: s for k, s in self.sessions.items() if s.core.epoch in self.group_keys}

    def _fresh(self, p) -> bool:
        age = self.clock.now() - (p.auth_ts + odid.ODID_EPOCH_2019)
        return -self.cfg.clock_skew_s <= age <= self.cfg.freshness_s

    def handle(self, raw: bytes) -> Result:
        t0 = time.perf_counter_ns()
        res = self._handle(raw)
        self.metrics.event("rx", status=res.status, us=(time.perf_counter_ns() - t0) / 1000,
                           session=res.session_id.hex() if res.session_id else None,
                           kind=res.pack.kind if res.pack else None, bytes=len(raw))
        return res

    def _handle(self, raw: bytes) -> Result:
        if framing.is_heartbeat(raw):
            return self._handle_heartbeat(raw)
        p = framing.parse_pack(raw)
        if p is None:
            return Result("malformed")
        sid = p.session_id
        if not self._fresh(p):
            return Result("stale", sid, p)
        s = self.sessions.get(sid)
        if s is None:
            return Result("unknown_session", sid, p)
        if p.seq <= s.last_seq:
            return Result("replay", sid, p)
        if not p.verify(s.core.pk):
            return Result("bad_sig", sid, p)
        s.last_seq = p.seq
        return Result("verified", sid, p, s)

    def _handle_heartbeat(self, raw: bytes) -> Result:
        hb = framing.parse_heartbeat(raw)
        if hb is None:
            return Result("malformed")
        sid = hb.session_id
        if not self._fresh(hb):
            return Result("stale", sid, hb)
        s = self.sessions.get(sid)
        if s is not None:  # already verified: only the cheap Wrapper check
            return Result("verified" if hb.verify(s.core.pk) else "bad_sig", sid, hb, s)

        core = Core.decode(hb.core)
        if core is None or core.session_id != sid:
            return Result("core_rejected", sid, hb)
        if not hb.verify(core.pk):  # Wrapper check (cheap) before GroupVerify
            return Result("core_rejected", sid, hb)
        grpkey = self.group_keys.get(core.epoch)
        if grpkey is None:
            # Newer than any key we hold: the receiver should fetch it (not a rejection).
            newer = core.epoch > max(self.group_keys, default=-1)
            return Result("future_epoch" if newer else "wrong_epoch", sid, hb)
        if not self.bucket.take():
            return Result("rate_limited", sid, hb)
        with self.metrics.timer("group_verify", scheme=core.scheme):
            ok = verify_core(self.scheme, grpkey, core)
        if not ok:
            return Result("core_rejected", sid, hb)
        s = self.sessions[sid] = Session(core, -1, self.clock.now())
        return Result("core_verified", sid, hb, s)
