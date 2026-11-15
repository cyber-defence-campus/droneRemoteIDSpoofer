"""Human-readable progress lines on stdout during a run.

Machine-readable data goes to the JSONL metrics; this is only the live overview.
Times are relative to CPBS_T0 (set by the scenario launcher, so all processes
share one time axis). CPBS_QUIET=1 silences everything.
"""
import os
import sys
import time

_T0 = float(os.environ.get("CPBS_T0", time.time()))
_QUIET = os.environ.get("CPBS_QUIET") == "1"
_COLOR = sys.stdout.isatty() or os.environ.get("CPBS_COLOR") == "1"

_ACTOR_COLORS = {"authority": "35", "sender": "36", "receiver": "32", "scenario": "33"}
RED, BOLD = "31", "1"


def _c(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _COLOR else s


def say(actor: str, msg: str, highlight: str = "") -> None:
    if _QUIET:
        return
    kind = actor.split(":")[0]
    name = actor.split(":")[-1]
    head = _c(_ACTOR_COLORS.get(kind, "0"), f"{name:<10}")
    print(f"[{time.time() - _T0:6.1f}s] {head} {_c(highlight, msg) if highlight else msg}", flush=True)


def short(session_id: bytes | str) -> str:
    return (session_id.hex() if isinstance(session_id, bytes) else session_id)[:8]
