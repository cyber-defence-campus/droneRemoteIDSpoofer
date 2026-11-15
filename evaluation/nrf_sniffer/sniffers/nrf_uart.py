"""
The nRF Sniffer for Bluetooth LE firmware (4.x, UART protocol 3) driven directly over its serial
port, without nrfutil.

Hop mode used to restart nrfutil for every mode switch, and on some hosts nrfutil takes from
milliseconds to over ten seconds before it reads the port again, so short dwells often never
reached the new mode. The firmware itself switches its scan PHY on a single REQ_SCAN_CONT command
within about a millisecond, on a scan already running.

Protocol: SLIP-framed packets (0xAB start, 0xBC end, 0xCD escape). Host commands carry the
protocol 1 header [6, payload length, 1, packet counter (16-bit LE), packet id]; firmware packets
carry [payload length (16-bit LE), protocol version, packet counter (16-bit LE), packet id]. An
advertising event packet continues with flags, channel, RSSI, event counter and the 32-bit
microsecond reception timestamp (see nordic_clock), then the access address and the PDU. The
firmware keeps a padding byte after the 2-byte PDU header (1M and Coded PHY); without it and
prefixed with the board byte, a firmware packet is the Nordic BLE (DLT 272) frame nrfutil writes
to its PCAPs.
"""

import collections
import errno
import fcntl
import logging
import os
import select
import termios
import time
from typing import Deque, Iterator, List, Optional

logger = logging.getLogger("CombinedRIDListener.NrfUart")

SLIP_START = 0xAB
SLIP_END = 0xBC
SLIP_ESC = 0xCD

REQ_FOLLOW = 0x00
EVENT_PACKET_ADV_PDU = 0x02
EVENT_PACKET_DATA_PDU = 0x06
REQ_SCAN_CONT = 0x07
SET_TEMPORARY_KEY = 0x0C
PING_REQ = 0x0D
PING_RESP = 0x0E
SET_ADV_CHANNEL_HOP_SEQ = 0x17
REQ_VERSION = 0x1B
RESP_VERSION = 0x1C
REQ_TIMESTAMP = 0x1D
RESP_TIMESTAMP = 0x1E

EVENT_PACKET_IDS = (EVENT_PACKET_ADV_PDU, EVENT_PACKET_DATA_PDU)
COMMAND_HEADER_LENGTH = 6
COMMAND_PROTOCOL_VERSION = 1
FIRMWARE_PROTOCOL_VERSION = 3
FIRMWARE_HEADER_LENGTH = 6
# Board byte that precedes each packet in a Nordic BLE (DLT 272) frame, as nrfutil writes it
DLT_BOARD_ID = 0x01
# Event packet layout after the firmware header: event header (its length first, then flags with
# the PHY in bits 4-6), access address, Coding Indicator on Coded PHY only, PDU, CRC
ACCESS_ADDRESS_LENGTH = 4
PHY_CODED = 2
PDU_HEADER_LENGTH = 2
CRC_LENGTH = 3

# REQ_SCAN_CONT flags
SCAN_FIND_SCAN_RSP = 0x01
SCAN_FOLLOW_AUX = 0x02
SCAN_CODED = 0x04

ADV_CHANNELS = (37, 38, 39)
DEFAULT_BAUDRATE = 1_000_000
BAUDRATES = {1_000_000: termios.B1000000, 460_800: termios.B460800}
WRAP_US = 2 ** 32
# Longest SLIP frame body accepted (a Nordic frame is at most a few hundred bytes)
MAX_FRAME = 1024
RESPONSE_TIMEOUT_S = 2.0


class NordicSnifferError(OSError):
    """The sniffer stopped answering or its serial port went away."""


def slip_encode(data: bytes) -> bytes:
    out = bytearray([SLIP_START])
    for b in data:
        if b in (SLIP_START, SLIP_END, SLIP_ESC):
            out += bytes([SLIP_ESC, b + 1])
        else:
            out.append(b)
    out.append(SLIP_END)
    return bytes(out)


class SlipDecoder:
    """Splits a byte stream into SLIP frame bodies; bytes outside a frame and oversized frames are dropped."""

    def __init__(self):
        self._frame: Optional[bytearray] = None
        self._escape = False
        self.discarded = 0

    def feed(self, data: bytes) -> List[bytes]:
        frames = []
        for b in data:
            if b == SLIP_START:
                if self._frame:
                    self.discarded += 1  # a frame without its end: lost bytes, start over
                self._frame, self._escape = bytearray(), False
            elif self._frame is None:
                continue
            elif b == SLIP_END:
                frames.append(bytes(self._frame))
                self._frame = None
            elif self._escape:
                self._frame.append(b - 1)
                self._escape = False
            elif b == SLIP_ESC:
                self._escape = True
            else:
                self._frame.append(b)
            if self._frame is not None and len(self._frame) > MAX_FRAME:
                self.discarded += 1
                self._frame = None
        return frames


def command_packet(counter: int, packet_id: int, payload: bytes = b"") -> bytes:
    """A host command, SLIP-framed."""
    header = bytes([COMMAND_HEADER_LENGTH, len(payload), COMMAND_PROTOCOL_VERSION]) + (counter & 0xFFFF).to_bytes(2, "little")
    return slip_encode(header + bytes([packet_id]) + bytes(payload))


def packet_id(packet: bytes) -> Optional[int]:
    """
    Packet id of a firmware packet, or None if its length does not match its header. The protocol
    version is not checked here: handshake() rejects a firmware of another protocol explicitly.
    """
    if len(packet) < FIRMWARE_HEADER_LENGTH:
        return None
    if len(packet) != FIRMWARE_HEADER_LENGTH + int.from_bytes(packet[0:2], "little"):
        return None
    return packet[5]


def payload(packet: bytes) -> bytes:
    return packet[FIRMWARE_HEADER_LENGTH:]


def without_padding(packet: bytes) -> bytes:
    """
    An event packet without the padding byte the firmware keeps after the PDU header, with its
    length lowered to match, as nrfutil passes it on. Whether the byte is there follows from the
    PDU length, so a packet without one is returned unchanged.
    """
    if packet_id(packet) not in EVENT_PACKET_IDS or len(packet) < FIRMWARE_HEADER_LENGTH + 2:
        return packet
    event_header = FIRMWARE_HEADER_LENGTH
    coded = (packet[event_header + 1] >> 4) & 0x07 == PHY_CODED
    pdu = event_header + packet[event_header] + ACCESS_ADDRESS_LENGTH + (1 if coded else 0)
    if len(packet) < pdu + PDU_HEADER_LENGTH:
        return packet
    if len(packet) - pdu != PDU_HEADER_LENGTH + 1 + packet[pdu + 1] + CRC_LENGTH:
        return packet
    length = int.from_bytes(packet[0:2], "little") - 1
    header_end = pdu + PDU_HEADER_LENGTH
    return length.to_bytes(2, "little") + packet[2:header_end] + packet[header_end + 1:]


def dlt_frame(packet: bytes) -> bytes:
    """The Nordic BLE (DLT 272) frame of a firmware packet, as stored in PCAPs."""
    return bytes([DLT_BOARD_ID]) + without_padding(packet)


class NordicSnifferUart:
    """
    The sniffer firmware on a serial port. Not thread-safe: one thread sends and reads. Packets
    that arrive while a command waits for its response are kept and returned by packets().
    """

    def __init__(self, port: str, baudrate: int = DEFAULT_BAUDRATE):
        self.port = port
        self.baudrate = baudrate
        self.fd: Optional[int] = None
        self._decoder = SlipDecoder()
        self._pending: Deque[bytes] = collections.deque()
        # How many of the kept packets arrived before the last response
        self._kept_before_response = 0
        self._counter = 0
        self.firmware_version: Optional[str] = None

    def open(self) -> None:
        if self.baudrate not in BAUDRATES:
            raise ValueError(f"Unsupported baud rate {self.baudrate}")
        try:
            fd = os.open(self.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
        except OSError as e:
            if e.errno == errno.EBUSY:
                raise NordicSnifferError(f"{self.port} is held exclusively by another program") from e
            raise
        try:
            # Exclusive use: a second reader on the port would split the byte stream between the two
            # (root can still open it; BleNrfSnifferThread therefore also waits until no other
            # process holds the port before it starts)
            fcntl.ioctl(fd, termios.TIOCEXCL)
            attrs = termios.tcgetattr(fd)
            cc = attrs[6]
            cc[termios.VMIN] = 0
            cc[termios.VTIME] = 0
            speed = BAUDRATES[self.baudrate]
            # Raw 8N1, no flow control, no echo or line processing
            termios.tcsetattr(fd, termios.TCSANOW,
                              [0, 0, termios.CS8 | termios.CREAD | termios.CLOCAL, 0, speed, speed, cc])
            # Input is kept, in order: flushing it would not empty the firmware's own queue, and
            # UartHopper drops everything that arrives before its first timestamp response (the
            # SLIP decoder skips a partial frame at the start)
            termios.tcflush(fd, termios.TCOFLUSH)
        except Exception:
            os.close(fd)
            raise
        self.fd = fd

    def close(self) -> None:
        if self.fd is not None:
            try:
                os.close(self.fd)
            except OSError as e:
                logger.warning(f"[!] Could not close the nRF sniffer's serial port: {e}")
            self.fd = None

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *exc):
        self.close()

    # Sending

    def send(self, packet_id_: int, payload_: bytes = b"") -> None:
        if self.fd is None:
            raise NordicSnifferError(f"{self.port} is not open")
        data = command_packet(self._counter, packet_id_, payload_)
        self._counter = (self._counter + 1) & 0xFFFF
        try:
            os.write(self.fd, data)
        except OSError as e:
            raise NordicSnifferError(f"Writing to {self.port} failed: {e}") from e

    def scan(self, coded: bool, follow_aux: bool = True, find_scan_rsp: bool = False) -> None:
        """Starts or changes the scan: advertising on LE Coded PHY (coded) or LE 1M, following aux packets."""
        flags = (SCAN_FIND_SCAN_RSP if find_scan_rsp else 0) | (SCAN_FOLLOW_AUX if follow_aux else 0) | (SCAN_CODED if coded else 0)
        self.send(REQ_SCAN_CONT, bytes([flags]))

    def set_adv_hop_sequence(self, channels=ADV_CHANNELS) -> None:
        channels = list(channels)
        if not 1 <= len(channels) <= 3 or any(c not in ADV_CHANNELS for c in channels):
            raise ValueError(f"Invalid advertising hop sequence {channels}")
        self.send(SET_ADV_CHANNEL_HOP_SEQ, bytes([len(channels)] + channels + [37] * (3 - len(channels))))

    # Receiving

    def _read(self, timeout: float) -> List[bytes]:
        """Packets that arrive within timeout (at least one read attempt)."""
        if self.fd is None:
            raise NordicSnifferError(f"{self.port} is not open")
        try:
            ready, _, _ = select.select([self.fd], [], [], max(0.0, timeout))
            if not ready:
                return []
            data = os.read(self.fd, 65536)
        except BlockingIOError:
            return []
        except OSError as e:
            raise NordicSnifferError(f"Reading {self.port} failed: {e}") from e
        if not data:
            # Readable but empty: the device was removed
            raise NordicSnifferError(f"{self.port} closed")
        return self._decoder.feed(data)

    def packets(self, timeout: float) -> Iterator[bytes]:
        """Yields the firmware packets that arrive within timeout seconds (kept ones first)."""
        while self._pending:
            yield self._pending.popleft()
        deadline = time.monotonic() + timeout
        while True:
            for packet in self._read(deadline - time.monotonic()):
                yield packet
            if time.monotonic() >= deadline:
                return

    def request(self, packet_id_: int, response_id: int, payload_: bytes = b"",
                timeout: float = RESPONSE_TIMEOUT_S) -> bytes:
        """
        Sends a command and returns its response packet. Other packets that arrive meanwhile, before
        or after the response, are kept in order; how many of them came before it is noted (see
        drop_packets_before_last_response).
        """
        self.send(packet_id_, payload_)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            batch = self._read(deadline - time.monotonic())
            for i, packet in enumerate(batch):
                if packet_id(packet) == response_id:
                    self._kept_before_response = len(self._pending)
                    self._pending.extend(batch[i + 1:])
                    return packet
                self._pending.append(packet)
        raise NordicSnifferError(f"No response {response_id:#04x} to command {packet_id_:#04x} on {self.port}")

    def drop_packets_before_last_response(self) -> int:
        """
        Drops the kept packets that arrived before the last response and returns how many. The
        firmware sends in order, so these are exactly the packets it had received before it
        answered, including any it queued while nothing read the port.
        """
        dropped = min(self._kept_before_response, len(self._pending))
        for _ in range(dropped):
            self._pending.popleft()
        self._kept_before_response = 0
        return dropped

    def timestamp(self) -> int:
        """The firmware's current 32-bit microsecond clock (the clock of the packets' timestamps)."""
        resp = payload(self.request(REQ_TIMESTAMP, RESP_TIMESTAMP))
        if len(resp) < 4:
            raise NordicSnifferError(f"Short timestamp response on {self.port}")
        return int.from_bytes(resp[0:4], "little")

    def handshake(self) -> str:
        """Checks that the port holds a sniffer firmware of protocol 3 and returns its version."""
        self.request(PING_REQ, PING_RESP)
        resp = self.request(REQ_VERSION, RESP_VERSION)
        if resp[2] != FIRMWARE_PROTOCOL_VERSION:
            raise NordicSnifferError(f"Sniffer on {self.port} speaks protocol {resp[2]}, not {FIRMWARE_PROTOCOL_VERSION}")
        self.firmware_version = payload(resp).rstrip(b"\0").decode(errors="replace")
        return self.firmware_version


# Scan settings per dwell. bt5: extended advertising on LE Coded PHY, following the aux packets
# that carry the Remote ID message pack. bt4: legacy advertising on LE 1M PHY.
SCAN_SETTINGS = {
    "bt5": {"coded": True, "follow_aux": True},
    "bt4": {"coded": False, "follow_aux": False},
}
# --ble-mode values: the dwells they cycle through (one entry: no switching)
MODE_SCHEDULES = {
    "hop": ("bt5", "bt4"),
    "extended": ("bt5",),
    "ble5": ("bt5",),
    "legacy": ("bt4",),
    "ble4": ("bt4",),
}
# Recent switches kept to label frames that arrive after the next switch (dongle buffers, bursts)
SWITCH_HISTORY = 8
# Longest wait for packets before the stop condition and the schedule are checked again
POLL_S = 0.2
# A timestamp request (a sync sample for the dongle clock mapping) at least this often
SYNC_INTERVAL_S = 5.0


def packet_time_us(packet: bytes) -> Optional[int]:
    """The dongle's reception timestamp of an advertising/data event packet (firmware packet, no board byte)."""
    if packet_id(packet) not in EVENT_PACKET_IDS or len(packet) < FIRMWARE_HEADER_LENGTH + 10:
        return None
    return int.from_bytes(packet[FIRMWARE_HEADER_LENGTH + 6:FIRMWARE_HEADER_LENGTH + 10], "little")


class UartHopper:
    """
    Scans with the sniffer firmware in the given BLE mode, switching BT5/BT4 in hop mode with one
    command per switch, and yields every captured frame with the mode it was captured in. That mode
    comes from the dongle time of each switch (REQ_TIMESTAMP right after the command), so frames
    that arrive after a later switch keep their own mode. Each timestamp response also goes to clock
    (a DongleClock) as a sync sample, at every switch and at least every SYNC_INTERVAL_S.

    Frames the dongle received before the run's first timestamp response are dropped (counted in
    dropped_before_start): the firmware queues what it receives while nothing reads the port, about
    40 s worth, and after a longer pause those frames are hours old. Their 32-bit microsecond time
    tells their age only modulo 71.6 minutes, so they cannot be dated. The firmware answers in
    order, so the response separates them exactly from the frames of this run.
    """

    def __init__(self, port: str, mode: str = "hop", bt5_dwell_s: float = 5.0, bt4_dwell_s: float = 1.0,
                 baudrate: int = DEFAULT_BAUDRATE, clock=None, adv_hop=None):
        if mode not in MODE_SCHEDULES:
            raise ValueError(f"Unknown BLE mode {mode}")
        self.uart = NordicSnifferUart(port, baudrate)
        self.schedule = MODE_SCHEDULES[mode]
        self.dwell_s = {"bt5": max(0.1, bt5_dwell_s), "bt4": max(0.1, bt4_dwell_s)}
        self.current_mode: Optional[str] = None
        self.firmware_version: Optional[str] = None
        self.clock = clock
        # Primary advertising channels the firmware hops over; None means the default 37/38/39.
        self.adv_hop = list(adv_hop) if adv_hop else None
        self._next_sync = 0.0
        self.dropped_before_start = 0
        # (dongle time of the switch, mode), oldest first
        self.switches: Deque = collections.deque(maxlen=SWITCH_HISTORY)

    def _sync(self) -> int:
        """The dongle's current time; passed to the clock mapping as a sync sample."""
        sent = time.monotonic()
        raw = self.uart.timestamp()
        if self.clock is not None:
            self.clock.sync(raw, sent, time.monotonic())
        self._next_sync = time.monotonic() + SYNC_INTERVAL_S
        return raw

    def _switch(self, mode: str) -> None:
        self.uart.scan(**SCAN_SETTINGS[mode])
        self.switches.append((self._sync(), mode))
        self.current_mode = mode

    def mode_of(self, packet: bytes) -> Optional[str]:
        """The mode the dongle was in when it received packet (None: before the first switch)."""
        fw = packet_time_us(packet)
        if fw is None:
            return self.current_mode
        for switched_at, mode in reversed(self.switches):
            if (fw - switched_at) % WRAP_US < WRAP_US // 2:  # received at or after this switch
                return mode
        return None

    def frames(self, stop=lambda: False) -> Iterator:
        """Yields (Nordic BLE frame, mode) until stop() returns True; raises NordicSnifferError on device loss."""
        self.uart.open()
        try:
            self.firmware_version = self.uart.handshake()
            self.uart.set_adv_hop_sequence(self.adv_hop or ADV_CHANNELS)
            index = 0
            self._switch(self.schedule[0])
            self.dropped_before_start = self.uart.drop_packets_before_last_response()
            next_switch = time.monotonic() + self.dwell_s[self.schedule[0]] if len(self.schedule) > 1 else None
            while not stop():
                now = time.monotonic()
                if next_switch is not None and now >= next_switch:
                    index = (index + 1) % len(self.schedule)
                    mode = self.schedule[index]
                    self._switch(mode)
                    next_switch = now + self.dwell_s[mode]
                    continue
                if now >= self._next_sync:
                    self._sync()
                wait = min(POLL_S, self._next_sync - now) if next_switch is None else min(POLL_S, next_switch - now)
                for packet in self.uart.packets(wait):
                    if packet_id(packet) in EVENT_PACKET_IDS:
                        yield dlt_frame(packet), self.mode_of(packet)
        finally:
            self.uart.close()
