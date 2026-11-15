"""Append-only audit log of opening/decryption requests (hash chain).

Each entry commits to its predecessor, so removing or editing an entry breaks
every later hash. A production system would publish the head (or use a Merkle
transparency log with inclusion proofs); the PoC exposes it via /audit.
"""
import hashlib
import json
import time
from typing import List

GENESIS = "0" * 64


class AuditLog:
    def __init__(self):
        self.entries: List[dict] = []

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, **record) -> dict:
        entry = {"index": len(self.entries), "time": time.time(), "prev": self.head, **record}
        entry["hash"] = _digest(entry)
        self.entries.append(entry)
        return entry

    def verify(self) -> bool:
        prev = GENESIS
        for e in self.entries:
            if e["prev"] != prev or e["hash"] != _digest({k: v for k, v in e.items() if k != "hash"}):
                return False
            prev = e["hash"]
        return True


def _digest(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
