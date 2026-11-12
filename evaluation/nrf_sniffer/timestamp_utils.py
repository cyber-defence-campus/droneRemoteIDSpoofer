#!/usr/bin/env python3
"""
Timestamp resolution and plausibility classification for drone Remote ID packets.

The reception timestamp is always the receiver's own clock as recorded at capture.
It is never replaced by drone-claimed times (ASTM System message) or times parsed
from encounter IDs. Implausible values are kept as recorded and flagged instead.
"""

import ctypes
import ctypes.util
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .parser import OPENDRONEID_EPOCH_2019

# Earliest plausible reception time: ASTM F3411 / OpenDroneID epoch (2019-01-01 UTC).
# Anything earlier (1970, 1972, 1995, ...) is an uninitialized or hardware-tick clock.
MIN_PLAUSIBLE_TIMESTAMP = float(OPENDRONEID_EPOCH_2019)
# Allowed forward offset relative to the checking clock before a timestamp counts as "future"
# (catches tick overflows such as 2061 while tolerating small clock differences between nodes).
MAX_FUTURE_SKEW_S = 86400.0

# Backward-compatible aliases (used for PCAP file routing and nRF replay plausibility checks)
DEFAULT_MIN_VALID_TIMESTAMP = MIN_PLAUSIBLE_TIMESTAMP
DEFAULT_MAX_CLOCK_SKEW_S = MAX_FUTURE_SKEW_S

# Packet-level anomaly codes for reception timestamps
ANOMALY_TIMESTAMP_MISSING = "timestamp_missing"
ANOMALY_TIMESTAMP_BEFORE_MIN = "timestamp_before_min"
ANOMALY_TIMESTAMP_IN_FUTURE = "timestamp_in_future"
ANOMALY_RECEIVER_CLOCK_UNSYNCED = "receiver_clock_unsynced"
# Time taken from an nrfutil PCAP (--rx-pcap replay) rather than host arrival; nrfutil derives it
# from accumulated dongle timer deltas, which can jump ahead by ~2^32 us on firmware glitches
ANOMALY_TIMESTAMP_FROM_NRF_PCAP = "timestamp_from_nrf_pcap"
# nRF live capture time not (yet) calibrated from the dongle clock: host arrival time, or the
# dongle clock before its offset settled; may be late by up to a few seconds
ANOMALY_TIMESTAMP_UNCALIBRATED = "timestamp_uncalibrated"

# Codes whose packets are kept in raw logs but excluded from encounter tracking,
# because the timestamp cannot be used to group packets into encounters.
ENCOUNTER_EXCLUDING_TIME_ANOMALIES = frozenset({
    ANOMALY_TIMESTAMP_MISSING,
    ANOMALY_TIMESTAMP_BEFORE_MIN,
    ANOMALY_TIMESTAMP_IN_FUTURE,
})


def parse_iso_timestamp(iso_str: str) -> Optional[float]:
    """Parses an ISO 8601 timestamp string into a UTC epoch float."""
    if not iso_str or not isinstance(iso_str, str):
        return None
    try:
        dt = datetime.fromisoformat(iso_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except Exception:
        return None


def format_iso_timestamp(ts: Optional[float]) -> Optional[str]:
    """Formats an epoch as UTC ISO 8601; None if it is missing or outside the representable range."""
    if ts is None:
        return None
    try:
        return datetime.fromtimestamp(float(ts), timezone.utc).isoformat()
    except (ValueError, TypeError, OverflowError, OSError):
        return None


def is_valid_timestamp(
    ts: Optional[float],
    min_valid: Optional[float] = None,
    max_skew_s: float = MAX_FUTURE_SKEW_S,
    ref_now: Optional[float] = None,
) -> bool:
    """Checks whether a numeric timestamp falls within plausible bounds."""
    if ts is None:
        return False
    try:
        val = float(ts)
    except (ValueError, TypeError):
        return False

    min_bound = min_valid if min_valid is not None else MIN_PLAUSIBLE_TIMESTAMP
    now = ref_now if ref_now is not None else time.time()
    return min_bound <= val <= now + max_skew_s


def get_recorded_timestamp(packet: Dict[str, Any]) -> Optional[float]:
    """
    Returns the reception timestamp recorded with the packet, without any plausibility
    filtering: reception_timestamp / timestamp / timestamp_epoch, then timestamp_iso.
    Returns None if the packet carries no parseable reception time.
    """
    for key in ("reception_timestamp", "timestamp", "timestamp_epoch"):
        raw_ts = packet.get(key)
        if raw_ts is None:
            continue
        try:
            return float(raw_ts)
        except (ValueError, TypeError):
            continue
    return parse_iso_timestamp(packet.get("timestamp_iso"))


def resolve_reception_timestamp(
    packet: Dict[str, Any],
    fallback_now: Optional[float] = None,
) -> float:
    """
    Returns the recorded reception timestamp as-is (implausible values included; classify
    them with classify_reception_timestamp). Only when the packet carries no reception time
    at all is fallback_now (default: time.time()) returned; such packets are flagged
    ANOMALY_TIMESTAMP_MISSING by classify_reception_timestamp.
    """
    recorded = get_recorded_timestamp(packet)
    if recorded is not None:
        return recorded
    return fallback_now if fallback_now is not None else time.time()


def classify_reception_timestamp(packet: Dict[str, Any], ref_now: Optional[float] = None) -> List[str]:
    """
    Returns timestamp anomaly codes for a packet's recorded reception time, checked against
    ref_now (default: this host's clock). An empty list means the timestamp is plausible.
    """
    recorded = get_recorded_timestamp(packet)
    if recorded is None:
        return [ANOMALY_TIMESTAMP_MISSING]
    now = ref_now if ref_now is not None else time.time()
    if recorded < MIN_PLAUSIBLE_TIMESTAMP:
        return [ANOMALY_TIMESTAMP_BEFORE_MIN]
    if recorded > now + MAX_FUTURE_SKEW_S:
        return [ANOMALY_TIMESTAMP_IN_FUTURE]
    return []


def add_anomalies(packet: Dict[str, Any], codes: List[str]) -> None:
    """Appends anomaly codes to the packet's "anomalies" list without duplicates."""
    if not codes:
        return
    existing = list(packet.get("anomalies") or [])
    for code in codes:
        if code not in existing:
            existing.append(code)
    packet["anomalies"] = existing


# Kernel NTP synchronization status (adjtimex)
_TIME_ERROR = 5  # adjtimex() return value when the clock is not synchronized (STA_UNSYNC)
_clock_sync_cache = {"checked_at": 0.0, "synced": None}


def _query_kernel_clock_synced() -> Optional[bool]:
    """Queries the kernel clock discipline via adjtimex(); None if unavailable (non-Linux)."""
    try:
        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return None
        libc = ctypes.CDLL(libc_name, use_errno=True)
        # struct timex is < 256 bytes on all Linux ABIs; modes (first field) = 0 means read-only
        buf = ctypes.create_string_buffer(512)
        state = libc.adjtimex(buf)
        if state < 0:
            return None
        return state != _TIME_ERROR
    except Exception:
        return None


def is_receiver_clock_synced(max_age_s: float = 10.0) -> Optional[bool]:
    """
    Returns whether this host's clock is NTP-synchronized according to the kernel
    (cached for max_age_s). None if the status cannot be determined.
    """
    now = time.monotonic()
    if _clock_sync_cache["checked_at"] == 0.0 or now - _clock_sync_cache["checked_at"] >= max_age_s:
        _clock_sync_cache["synced"] = _query_kernel_clock_synced()
        _clock_sync_cache["checked_at"] = now
    return _clock_sync_cache["synced"]
