"""Receiver process: UDP -> tiered CPBS verification -> verified tracks.

Untrusted receivers (default) only verify. A trusted receiver (--trusted)
additionally asks the authority to open every new session and to decrypt its
C_enc (responder tier), logging both results.

Run:  python -m cpbs.receiver.main --config scenarios/basic.json --listen 127.0.0.1:8472
"""
import argparse
import json
import signal
import socket
import time
from collections import Counter, defaultdict

from cpbs.authority.client import AuthorityClient
from cpbs.clock import Clock
from cpbs.config import Config
from cpbs.console import RED, say, short
from cpbs.crypto.groupsig import GroupScheme
from cpbs.metrics import Metrics
from cpbs.odid.parser import decode_astm_message
from cpbs.odid import messages as odid
from cpbs.protocol.core import FIELD_OPERATOR_LOCATION, FIELD_SERIAL
from cpbs.protocol import framing
from cpbs.protocol.verifier import Verifier

FIELD_NAMES = {str(FIELD_SERIAL): "serial", str(FIELD_OPERATOR_LOCATION): "operator_location"}

EPOCH_POLL_S = 1.0
STATUS_EVERY_S = 10.0
# Rejections worth a line (printed once per session); everything else only in the status counts.
REJECTIONS = {"wrong_epoch": "old-epoch Core (revoked or stale credentials)",
              "core_rejected": "invalid Core / group signature",
              "rate_limited": "new-session rate limit hit",
              "bad_sig": "bad pack signature", "replay": "replayed pack", "stale": "stale pack"}


class Receiver:
    def __init__(self, cfg: Config, listen: str, metrics: Metrics, name: str, trusted: bool = False):
        self.cfg, self.metrics, self.name, self.trusted = cfg, metrics, name, trusted
        self.actor = f"receiver:{name}"
        self.reported = set()                 # (session, status) already printed
        self.window = Counter()               # statuses since the last status line
        self.authority = AuthorityClient(cfg.authority_url)
        self.verifier = Verifier(GroupScheme(cfg.scheme), cfg, Clock(), metrics)
        self.epoch = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        host, port = listen.rsplit(":", 1)
        self.sock.bind((host, int(port)))
        self.sock.settimeout(0.2)
        self.stats = Counter()
        self.first_seen = {}                  # session -> first rx time
        self.tracks = defaultdict(list)       # session -> [(t, lat, lon)]

    def refresh_epoch(self) -> None:
        epoch, _, gpk = self.authority.current()
        if epoch != self.epoch:
            dropped = len(self.verifier.sessions)
            self.verifier.set_group_key(epoch, gpk)
            dropped -= len(self.verifier.sessions)
            self.metrics.event("epoch", epoch=epoch)
            say(self.actor, f"group key for epoch {epoch} loaded"
                            + (f", dropped {dropped} sessions of the old epoch" if self.epoch is not None and dropped else ""))
            self.epoch = epoch

    def on_core_verified(self, sid: bytes, session) -> None:
        latency = time.time() - self.first_seen[sid]
        self.metrics.event("session_verified", session=sid.hex(), epoch=session.core.epoch, latency_s=latency)
        say(self.actor, f"session {short(sid)} verified: group member, epoch {session.core.epoch} "
                        f"({latency:.1f}s after its first packet)")
        if not self.trusted:
            return
        t0 = time.perf_counter_ns()
        opened = self.authority.open(session.core.encode(), requester=self.name, ticket=f"auto-{sid.hex()[:8]}")
        t1 = time.perf_counter_ns()
        fields = self.authority.decrypt(session.core.c_enc, requester=self.name, ticket="auto", session=sid.hex())
        t2 = time.perf_counter_ns()
        named = {str(k): v.decode(errors="replace") for k, v in fields.items()}
        self.metrics.event("opened", session=sid.hex(), member=opened["member_id"], epoch=opened["epoch"],
                           open_rtt_us=(t1 - t0) / 1000,
                           decrypt_rtt_us=(t2 - t1) / 1000, fields=named)
        say(self.actor, f"opened {short(sid)} -> member '{opened['member_id']}' (audit #{opened['audit_index']}, "
                        f"{(t1 - t0) / 1e6:.1f} ms); C_enc: " + ", ".join(f"{FIELD_NAMES.get(k, k)}={v}" for k, v in named.items()))

    def run(self, duration: float) -> dict:
        t_end = time.time() + duration
        last_poll = 0.0
        last_status = time.time()
        while time.time() < t_end:
            if time.time() - last_poll >= EPOCH_POLL_S:
                last_poll = time.time()
                self.refresh_epoch()
            if time.time() - last_status >= STATUS_EVERY_S:
                self.print_status(time.time() - last_status)
                last_status = time.time()
            try:
                raw, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            res = self.verifier.handle(raw)
            self.stats[res.status] += 1
            self.window[res.status] += 1
            if res.status == "future_epoch":
                say(self.actor, f"session {short(res.session_id)} uses a newer epoch; fetching its group key")
                self.refresh_epoch()  # the next heartbeat of this session will then verify
            if res.status in REJECTIONS and (res.session_id, res.status) not in self.reported:
                self.reported.add((res.session_id, res.status))
                say(self.actor, f"rejected session {short(res.session_id)}: {REJECTIONS[res.status]}", RED)
            if res.session_id is not None:
                self.first_seen.setdefault(res.session_id, time.time())
            if res.status == "core_verified":
                self.on_core_verified(res.session_id, res.session)
            elif res.status == "verified" and res.pack.kind == framing.KIND_DATA:
                loc = decode_astm_message(res.pack.message(odid.MsgType.LOCATION))
                self.tracks[res.session_id].append((time.time(), loc["lat"], loc["lon"]))
        return self.summary()

    def print_status(self, dt: float) -> None:
        w, self.window = self.window, Counter()
        ok = w["verified"] + w["core_verified"]
        say(self.actor, f"last {dt:.0f}s: {ok} packs/heartbeats verified, "
                        f"{w['unknown_session']} data packs dropped (no Core yet), "
                        f"{sum(w[k] for k in REJECTIONS)} rejected; {len(self.verifier.sessions)} active sessions")

    def summary(self) -> dict:
        return {"receiver": self.name, "trusted": self.trusted, "status_counts": dict(self.stats),
                "sessions_verified": len(self.verifier.sessions),
                "track_points": sum(len(t) for t in self.tracks.values())}


def _stop(*_):
    raise KeyboardInterrupt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--listen", default="127.0.0.1:8472")
    ap.add_argument("--name", default="receiver")
    ap.add_argument("--trusted", action="store_true")
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--metrics")
    ap.add_argument("--summary")
    a = ap.parse_args()
    signal.signal(signal.SIGTERM, _stop)
    metrics = Metrics(a.metrics, f"receiver:{a.name}")
    r = Receiver(Config.load(a.config), a.listen, metrics, a.name, a.trusted)
    try:
        r.run(a.duration)
    except KeyboardInterrupt:
        pass
    finally:
        summary = r.summary()
        metrics.event("summary", **summary)
        metrics.close()
        if a.summary:
            with open(a.summary, "w") as f:
                json.dump(summary, f, indent=2)
        say(f"receiver:{a.name}", f"finished: {summary['sessions_verified']} sessions verified, "
                                 f"{summary['track_points']} track points, statuses {summary['status_counts']}")


if __name__ == "__main__":
    main()
