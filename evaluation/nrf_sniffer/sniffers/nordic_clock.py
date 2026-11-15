"""
Reception times of nRF sniffer frames from the dongle's own clock.

Every frame the nRF Sniffer firmware sends carries a 32-bit microsecond timestamp taken when the
radio received it. Host arrival times are no substitute: frames reach the scanner in bursts, after
nrfutil starts (it first delivers what the dongle received while no nrfutil was running) and
whenever the pipe is read late, so arrival lags reception by up to seconds. nrfutil's own PCAP
times are no better: it counts dongle time forward from its own start, so every restart (each
mode switch in hop mode) misdates the frames buffered before it.

The dongle clock runs continuously and drifts by a few ppm against an NTP-disciplined host (1-3 ppm
measured). It is mapped to host time by sync samples: the scanner asks the firmware for its clock
(a timestamp request) at every mode switch and every few seconds, noting the host time before
sending (sent) and once the answer has been read (arrival). The firmware read its counter in
between, so a sample bounds the offset (host - dongle time) to [sent - dongle, arrival - dongle]
(Cristian's algorithm). The estimate is the middle of that interval for the sample with the
shortest round trip of the last SYNCED_WINDOW_S: off by at most half that round trip, and a window
in which some answers were slow does not move it.

Before the first sync sample (and for replayed captures, which have none), the smallest offset of
the frames over a sliding window is used: the frame that reached the host fastest bounds the offset
from above. When that window holds only late frames (a quiet spell), the last good offset,
extrapolated by the largest plausible drift, bounds the estimate. The offset is kept on the
monotonic clock, so NTP steps of the host clock cannot distort it.
"""

import collections
import time
from typing import Callable, Deque, Optional, Tuple

# Nordic BLE (DLT 272) header: board(1) | hdr_len(1) payload_len(1) proto(1) pkt_counter(2)
# pkt_id(1) | packet header: len(1) flags(1) channel(1) rssi(1) event_counter(2) timestamp(4)
PACKET_IDS_WITH_TIMESTAMP = (0x02, 0x06)  # EVENT_PACKET_ADV_PDU, EVENT_PACKET_DATA_PDU
PACKET_HEADER_OFFSET = 7
MIN_PACKET_HEADER_LEN = 10

WRAP_US = 2 ** 32
# Offsets of the fastest frames over this window define the mapping (drift over it: ~0.1 ms)
OFFSET_WINDOW_S = 120.0
# Sync samples of this long a window compete for the shortest round trip; a short window follows
# drift closely (30 s at 3 ppm: 0.09 ms)
SYNCED_WINDOW_S = 30.0
# The offset cannot grow faster than the two clocks drift apart (measured ~1 ppm, crystals stay
# well within this): after a quiet spell with only late frames, the last good offset plus this
# rate bounds the estimate instead of a late frame's offset
MAX_DRIFT_RATE = 50e-6
# Until frames from this long have been seen, the offset may still be too large (no prompt frame yet)
SETTLE_S = 10.0
# A frame cannot arrive before it was received (beyond jitter), nor this long after: either means
# the dongle clock restarted (dongle reset or replugged)
MAX_LEAD_S = 1.0
MAX_DELAY_S = 600.0


def firmware_time_us(data: bytes) -> Optional[int]:
    """The dongle's reception timestamp (µs, 32-bit) of a Nordic BLE frame, or None if it has none."""
    if len(data) <= PACKET_HEADER_OFFSET or data[6] not in PACKET_IDS_WITH_TIMESTAMP:
        return None
    hdr_len = data[PACKET_HEADER_OFFSET]
    end = PACKET_HEADER_OFFSET + hdr_len
    if hdr_len < MIN_PACKET_HEADER_LEN or len(data) < end:
        return None
    return int.from_bytes(data[end - 4:end], "little")


class DongleClock:
    """Maps dongle timestamps to host (UTC) reception times; one instance per dongle and run."""

    def __init__(self, monotonic: Callable[[], float] = time.monotonic, wall: Callable[[], float] = time.time):
        self._monotonic = monotonic
        self._wall = wall
        self.resets = 0
        self._restart()

    def _restart(self):
        # Unwrapped dongle time (µs) the next reading is unwrapped against: the last sync sample
        # once synced, otherwise the last frame
        self._reference: Optional[int] = None
        self._synced = False
        self._started: Optional[float] = None
        # (arrival, offset) with increasing offsets: the front is the window minimum
        self._window: Deque[Tuple[float, float]] = collections.deque()
        # (arrival, offset) of the sample that set the current estimate
        self._anchor: Optional[Tuple[float, float]] = None
        # Sync samples of the last SYNCED_WINDOW_S: (arrival, offset at the middle of the round trip, round trip)
        self._samples: Deque[Tuple[float, float, float]] = collections.deque()

    def _estimate(self, now: float) -> float:
        """
        Once synced, the offset of the sample with the shortest round trip in the window (the latest
        of equal ones); before, the window minimum of the frames, capped by the anchor's offset plus
        the largest plausible drift since.
        """
        if self._samples:
            return min(self._samples, key=lambda s: (s[2], -s[0]))[1]
        front = self._window[0]
        if self._anchor is not None:
            cap = self._anchor[1] + MAX_DRIFT_RATE * (now - self._anchor[0])
            if cap < front[1]:
                return cap
        self._anchor = front
        return front[1]

    def _dongle_seconds(self, raw_us: int, is_sync: bool = False) -> float:
        """Unwraps the 32-bit counter to the reading nearest the reference (within half a wrap)."""
        value = raw_us
        if self._reference is not None:
            value += round((self._reference - raw_us) / WRAP_US) * WRAP_US
        if is_sync or not self._synced:
            self._reference = value
        return value / 1e6

    def _add(self, now: float, offset: float) -> None:
        if self._started is None:
            self._started = now
        while self._window and self._window[-1][1] >= offset:
            self._window.pop()
        self._window.append((now, offset))
        window_s = SYNCED_WINDOW_S if self._synced else OFFSET_WINDOW_S
        while self._window[0][0] < now - window_s:
            self._window.popleft()

    def sync(self, raw_us: int, sent: float, arrival: Optional[float] = None) -> None:
        """
        A sync sample: the firmware's answer to a timestamp request sent at monotonic time sent and
        read at arrival (now if omitted). It fixes the offset at once, so frames that reach the host
        late also get their exact time. Once synced, only a sample that disagrees with the offset
        signals a dongle restart; frames may then arrive arbitrarily late without being taken for
        one. Sync samples then also follow the drift, so they must come regularly (UartHopper takes
        one at every mode switch and every few seconds).
        """
        now = self._monotonic() if arrival is None else arrival
        round_trip = max(0.0, now - sent)
        offset = now - round_trip / 2 - self._dongle_seconds(raw_us, is_sync=True)
        if (self._samples or self._window) and abs(offset - self._estimate(now)) > MAX_LEAD_S:
            self.resets += 1
            self._restart()
            offset = now - round_trip / 2 - self._dongle_seconds(raw_us, is_sync=True)
        if self._started is None:
            self._started = now
        self._synced = True
        self._samples.append((now, offset, round_trip))
        while self._samples[0][0] < now - SYNCED_WINDOW_S:
            self._samples.popleft()

    def reception_time(self, raw_us: int, arrival: Optional[float] = None) -> Tuple[float, bool]:
        """
        Returns (UTC reception time, settled) of a frame with dongle timestamp raw_us that reached
        the host at arrival (monotonic; now if omitted). settled is False while the offset may
        still be too large, i.e. the time may be late by up to the arrival delay.
        """
        now = self._monotonic() if arrival is None else arrival
        dongle_s = self._dongle_seconds(raw_us)
        offset = now - dongle_s
        if not self._synced:
            if self._window:
                current = self._estimate(now)
                if offset < current - MAX_LEAD_S or offset > current + MAX_DELAY_S:
                    self.resets += 1
                    self._restart()
                    dongle_s = self._dongle_seconds(raw_us)
                    offset = now - dongle_s
            self._add(now, offset)
        # Once synced, only sync samples set the offset: a frame is mapped, never trusted to adjust it
        # (a queued frame older than half a counter wrap would be misdated and pull it off)
        reception_monotonic = dongle_s + self._estimate(now)
        settled = self._synced or now - self._started >= SETTLE_S
        return reception_monotonic + (self._wall() - self._monotonic()), settled
