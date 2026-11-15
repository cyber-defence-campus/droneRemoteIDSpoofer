"""JSONL event/timing log; one file per process, analysed by bench/analyze.py."""
import json
import time
from contextlib import contextmanager
from typing import Optional, TextIO


class Metrics:
    def __init__(self, path: Optional[str] = None, actor: str = ""):
        self._f: Optional[TextIO] = open(path, "a", buffering=1) if path else None
        self.actor = actor

    def event(self, name: str, **fields) -> None:
        if self._f:
            self._f.write(json.dumps({"t": time.time(), "actor": self.actor, "event": name, **fields}) + "\n")

    @contextmanager
    def timer(self, name: str, **fields):
        t0 = time.perf_counter_ns()
        yield
        self.event(name, us=(time.perf_counter_ns() - t0) / 1000, **fields)

    def close(self) -> None:
        if self._f:
            self._f.close()


NULL = Metrics()
