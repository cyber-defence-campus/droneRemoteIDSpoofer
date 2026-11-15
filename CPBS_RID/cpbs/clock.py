"""Injectable clock so tests can drive time (freshness windows, epochs)."""
import time


class Clock:
    def now(self) -> float:
        return time.time()


class ManualClock(Clock):
    def __init__(self, t: float = 1_780_000_000.0):
        self.t = t

    def now(self) -> float:
        return self.t

    def advance(self, dt: float) -> None:
        self.t += dt

