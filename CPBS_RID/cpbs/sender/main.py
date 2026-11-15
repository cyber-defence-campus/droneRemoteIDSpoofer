"""Sender (drone) process: enrol, fly a synthetic trajectory, broadcast CPBS packs over UDP.

Run:  python -m cpbs.sender.main --config scenarios/basic.json --serial SN-001 --operator CHEop001
"""
import argparse
import math
import random
import signal
import socket
import time
from dataclasses import dataclass
from typing import Optional

from cpbs.authority.client import AuthorityClient
from cpbs.clock import Clock
from cpbs.config import Config
from cpbs.console import RED, say, short
from cpbs.crypto import seal
from cpbs.crypto.groupsig import GroupScheme
from cpbs.metrics import Metrics
from cpbs.odid import messages as odid
from cpbs.protocol.core import FIELD_SERIAL, encode_fields
from cpbs.protocol.session import SenderSession

M_PER_DEG = 111_320.0
STATUS_EVERY_S = 10.0


@dataclass
class Trajectory:
    """Random walk with smoothly changing heading, from a fixed take-off point."""
    lat: float
    lon: float
    heading: float = 0.0
    speed: float = 8.0
    height: float = 60.0

    def step(self, dt: float, rng: random.Random) -> None:
        self.heading = (self.heading + rng.uniform(-15, 15)) % 360
        d = self.speed * dt
        self.lat += d * math.cos(math.radians(self.heading)) / M_PER_DEG
        self.lon += d * math.sin(math.radians(self.heading)) / (M_PER_DEG * math.cos(math.radians(self.lat)))


class Drone:
    def __init__(self, cfg: Config, serial: str, operator: str, lat: float, lon: float,
                 metrics: Metrics, clock: Clock = Clock(), seed: Optional[int] = None):
        self.cfg, self.serial, self.operator = cfg, serial, operator
        self.metrics, self.clock = metrics, clock
        self.scheme = GroupScheme(cfg.scheme)
        self.authority = AuthorityClient(cfg.authority_url)
        self.responder_pk = self.authority.responder_pk()
        # US model: per-drone membership (opening yields the serial);
        # EU model: per-operator membership (opening yields the operator ID).
        # C_enc carries the serial in both, for responders without the opening key.
        self.member_id = serial if cfg.membership == "drone" else operator
        self.fields = {FIELD_SERIAL: serial.encode()}
        self.home = (int(lat * 1e7), int(lon * 1e7))
        self.traj = Trajectory(lat, lon, heading=random.Random(seed).uniform(0, 360))
        self.rng = random.Random(seed)
        self.epoch, self.keys, self.session = None, None, None
        self.revoked = False
        self.actor = f"sender:{serial}"
        self.tx_packs = self.tx_bytes = 0
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.targets = [(h, int(p)) for h, p in (a.rsplit(":", 1) for a in cfg.receivers)]

    def enrol_if_needed(self) -> bool:
        """Enrol in the current epoch; returns True if the credentials changed."""
        epoch, _, gpk = self.authority.current()
        if epoch == self.epoch or self.revoked:
            return False
        try:
            t0 = time.perf_counter_ns()
            memkey = self.authority.enroll(self.scheme, self.member_id, epoch, gpk)
            us = (time.perf_counter_ns() - t0) / 1000
            self.metrics.event("enrol", epoch=epoch, us=us)
            say(self.actor, f"enrolled as '{self.member_id}' in epoch {epoch} ({us / 1000:.1f} ms)")
        except PermissionError as e:
            # Revoked: keep broadcasting with the old credentials (receivers must reject them).
            self.revoked = True
            self.metrics.event("enrol_refused", epoch=epoch, reason=str(e))
            say(self.actor, f"enrolment in epoch {epoch} refused ({e}); "
                            f"continuing with epoch-{self.epoch} credentials", RED)
            return False
        self.epoch, self.keys = epoch, self.scheme.signing_keys(memkey, gpk)
        return True

    def new_session(self) -> None:
        c_enc = seal.seal(self.responder_pk, encode_fields(self.fields))  # fresh per session
        self.session = SenderSession(self.scheme, self.keys, self.epoch, c_enc, self.clock.now(), self.metrics)
        hb = len(self.session.heartbeat(self.clock.now()))
        say(self.actor, f"new session {short(self.session.session_id)} (epoch {self.epoch}, "
                        f"Core {len(self.session.core_bytes)} B, heartbeat frame {hb} B)")

    def send(self, pack: bytes, kind: str) -> None:
        for t in self.targets:
            self.sock.sendto(pack, t)
        self.tx_packs += 1
        self.tx_bytes += len(pack)
        self.metrics.event("tx", kind=kind, bytes=len(pack), session=self.session.session_id.hex(),
                           seq=self.session.seq - 1)

    def run(self, duration: float) -> None:
        self.enrol_if_needed()
        if self.keys is None:
            raise SystemExit(f"{self.member_id}: enrolment refused")
        self.new_session()
        last_hb = last_epoch_check = -math.inf
        last_status = self.clock.now()
        period = 1.0 / self.cfg.data_rate_hz
        next_tick = self.clock.now()
        t_end = next_tick + duration
        while self.clock.now() < t_end:
            now = self.clock.now()
            rotate = now - self.session.started >= self.cfg.session_lifetime_s
            if now - last_epoch_check >= self.cfg.heartbeat_interval_s:
                last_epoch_check = now
                rotate |= self.enrol_if_needed()  # new epoch credentials -> new session
            if rotate:
                self.new_session()
                last_hb = -math.inf
            if now - last_hb >= self.cfg.heartbeat_interval_s:
                last_hb = now
                self.send(self.session.heartbeat(now), "heartbeat")
            self.traj.step(period, self.rng)
            loc = odid.build_location_vector(int(self.traj.lat * 1e7), int(self.traj.lon * 1e7),
                                             int(self.traj.heading), now, speed=self.traj.speed,
                                             height=self.traj.height, geodetic_altitude=self.traj.height + 400)
            sysm = odid.build_system(self.home[0], self.home[1], now)
            self.send(self.session.data_pack(loc, sysm, now), "data")
            if now - last_status >= STATUS_EVERY_S:
                say(self.actor, f"sent {self.tx_packs} packs ({self.tx_bytes / (now - last_status):.0f} B/s) "
                                f"in the last {now - last_status:.0f}s")
                last_status, self.tx_packs, self.tx_bytes = now, 0, 0
            next_tick += period
            time.sleep(max(0.0, next_tick - self.clock.now()))


def _stop(*_):
    raise KeyboardInterrupt


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--config")
    ap.add_argument("--serial", required=True)
    ap.add_argument("--operator", default="CHEop000000000")
    ap.add_argument("--lat", type=float, default=47.3769)
    ap.add_argument("--lon", type=float, default=8.5417)
    ap.add_argument("--duration", type=float, default=30.0)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--metrics")
    a = ap.parse_args()
    signal.signal(signal.SIGTERM, _stop)
    metrics = Metrics(a.metrics, f"sender:{a.serial}")
    try:
        Drone(Config.load(a.config), a.serial, a.operator, a.lat, a.lon, metrics, seed=a.seed).run(a.duration)
    except KeyboardInterrupt:
        pass
    finally:
        metrics.close()


if __name__ == "__main__":
    main()
