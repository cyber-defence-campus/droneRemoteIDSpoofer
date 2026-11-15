"""PoC configuration (loaded from a scenario JSON, defaults below)."""
import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path


@dataclass
class Config:
    scheme: str = "bbs04"                # group signature scheme (only bbs04)
    membership: str = "drone"            # drone (US: per-drone keys) | operator (EU: per-operator keys)
    freshness_s: float = 2.0             # Δ: max age of a pack's Auth timestamp
    clock_skew_s: float = 1.0            # tolerated sender clock ahead of receiver
    data_rate_hz: float = 1.0            # telemetry packs per second
    heartbeat_interval_s: float = 3.0    # Core re-broadcast period
    session_lifetime_s: float = 60.0     # session rotation period
    max_new_sessions_per_s: float = 20.0 # receiver rate limit on group verifications
    authority_url: str = "http://127.0.0.1:8471"
    receivers: list = field(default_factory=lambda: ["127.0.0.1:8472"])  # UDP host:port

    @classmethod
    def load(cls, path: str | Path | None = None, **overrides) -> "Config":
        data = json.loads(Path(path).read_text()).get("config", {}) if path else {}
        data.update({k: v for k, v in overrides.items() if v is not None})
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})

    def to_dict(self) -> dict:
        return asdict(self)
