"""ASTM F3411-22a message encoding.

Basic ID / Location / System / Operator ID builders are adapted from
droneRemoteIDSpoofer @ 3b36307 (drone_rid_spoofer/messages.py): the
DroneState dependency is removed and timestamps are passed explicitly.

CPBS additions: Basic ID with a Specific Session ID, Authentication pages,
message pack encode/decode and raw Authentication reassembly.
"""
import struct
from enum import IntEnum
from typing import List, Optional, Tuple

PROTOCOL_VERSION = 2
MSG_SIZE = 25
PACK_MAX_MESSAGES = 9
ODID_EPOCH_2019 = 1546300800  # 2019-01-01 00:00:00 UTC

# Authentication message capacity (F3411-22a): page 0 carries 17 data bytes,
# pages 1..15 carry 23; the Length field is one byte.
AUTH_PAGE0_DATA = 17
AUTH_PAGEN_DATA = 23
AUTH_MAX_PAGES = 16
AUTH_MAX_LENGTH = 255

ID_TYPE_SERIAL = 1
ID_TYPE_SESSION = 4
UA_TYPE_MULTIROTOR = 2
AUTH_TYPE_SAM = 5  # Specific Authentication Method


class MsgType(IntEnum):
    BASIC_ID = 0x0
    LOCATION = 0x1
    AUTH = 0x2
    SELF_ID = 0x3
    SYSTEM = 0x4
    OPERATOR_ID = 0x5
    PACK = 0xF


def msg_type(block: bytes) -> int:
    return block[0] >> 4


def _header(t: MsgType) -> int:
    return (t << 4) | PROTOCOL_VERSION


def _transform_rotation(rotation: int) -> Tuple[int, int]:
    """Transform rotation value according to ASTM F3411-19."""
    rotation = max(0, min(359, rotation))
    if rotation < 180:
        return rotation, 32
    else:
        return rotation - 180, 34


def _encode_speed(speed_mps: float) -> int:
    """Encode speed (m/s) as uint8 in 0.25 m/s units (multiplier bit assumed 0)."""
    return max(0, min(255, int(round(speed_mps / 0.25))))


def _encode_vertical_speed(vs_mps: float) -> int:
    """Encode vertical speed (m/s) as int8 in 0.5 m/s units."""
    return max(-127, min(127, int(round(vs_mps / 0.5))))


def _encode_altitude(alt_m: float) -> int:
    """Encode altitude/height (m) as uint16: (alt + 1000) * 2."""
    return max(0, min(0xFFFF, int(round((alt_m + 1000.0) * 2))))


def odid_timestamp(unix_time: float) -> int:
    """Seconds since 2019-01-01 UTC, as used by Authentication and System messages."""
    return max(0, int(unix_time) - ODID_EPOCH_2019)


def build_basic_id(serial: bytes) -> bytes:
    """Build Message Type 0 - Basic ID with a serial number (25 bytes)."""
    header = bytes([_header(MsgType.BASIC_ID), (ID_TYPE_SERIAL << 4) | UA_TYPE_MULTIROTOR])
    return header + struct.pack("<20s", serial) + b'\x00\x00\x00'


def build_basic_id_session(session_id_type: int, session_id: bytes) -> bytes:
    """Build Basic ID with ID type 4 (Specific Session ID).

    The UAS ID field starts with the session ID type byte, followed by the
    session ID (at most 19 bytes).
    """
    if len(session_id) > 19:
        raise ValueError("session ID longer than 19 bytes")
    uas_id = bytes([session_id_type]) + session_id
    header = bytes([_header(MsgType.BASIC_ID), (ID_TYPE_SESSION << 4) | UA_TYPE_MULTIROTOR])
    return header + struct.pack("<20s", uas_id) + b'\x00\x00\x00'


def parse_basic_id_session(block: bytes) -> Optional[Tuple[int, bytes]]:
    """Return (session_id_type, raw UAS ID bytes after the type) for a type-4 Basic ID."""
    if msg_type(block) != MsgType.BASIC_ID or (block[1] >> 4) != ID_TYPE_SESSION:
        return None
    return block[2], block[3:22]


def build_location_vector(lat: int, lng: int, direction: int,
                          unix_time: float,
                          speed: float = 0.0,
                          vertical_speed: float = 0.0,
                          pressure_altitude: float = 0.0,
                          geodetic_altitude: float = 0.0,
                          height: float = 0.0) -> bytes:
    """Build Message Type 1 - Location/Vector (25 bytes).

    lat/lng are in 1e-7 degrees. The timestamp field holds tenths of a
    second since the start of the current UTC hour.
    """
    dir_val, ew_dir = _transform_rotation(direction)
    tenth_seconds = int((unix_time % 3600) * 10)

    return b''.join([
        struct.pack("<B", _header(MsgType.LOCATION)),
        struct.pack("<B", ew_dir),
        struct.pack("<B", dir_val),
        struct.pack("<B", _encode_speed(speed)),
        struct.pack("<b", _encode_vertical_speed(vertical_speed)),
        struct.pack("<i", lat),
        struct.pack("<i", lng),
        struct.pack("<H", _encode_altitude(pressure_altitude)),
        struct.pack("<H", _encode_altitude(geodetic_altitude)),
        struct.pack("<H", _encode_altitude(height)),
        b'\x00\x00',
        struct.pack("<H", tenth_seconds),
        b'\x00\x00'
    ])


def build_system(pilot_lat: int, pilot_lng: int, unix_time: float = 0.0) -> bytes:
    """Build Message Type 4 - System (25 bytes)."""
    return b''.join([
        struct.pack("<B", _header(MsgType.SYSTEM)),
        struct.pack("<B", 0x05),
        struct.pack("<i", pilot_lat),
        struct.pack("<i", pilot_lng),
        b'\x00\x00\x00\x00\x00\x00\x00',
        struct.pack("<B", 0x12),
        b'\x00\x00',
        struct.pack("<I", odid_timestamp(unix_time) if unix_time else 0),
        b'\x00'
    ])


def build_operator_id(operator_id: str = "") -> bytes:
    """Build Message Type 5 - Operator ID (25 bytes)."""
    header = bytes([_header(MsgType.OPERATOR_ID), 0x00])
    body = operator_id.encode('ascii', errors='ignore')[:20].ljust(20, b'\x00')
    return header + body + b'\x00\x00\x00'


# --- Authentication (Type 2) ------------------------------------------------

def auth_pages_needed(length: int) -> int:
    if length <= AUTH_PAGE0_DATA:
        return 1
    return 1 + -(-(length - AUTH_PAGE0_DATA) // AUTH_PAGEN_DATA)


def auth_capacity(pages: int) -> int:
    """Auth data bytes that fit into the given number of pages."""
    return min(AUTH_MAX_LENGTH, AUTH_PAGE0_DATA + (pages - 1) * AUTH_PAGEN_DATA)


def build_auth_pages(auth_type: int, data: bytes, odid_ts: int) -> List[bytes]:
    """Split authentication data into Authentication message pages.

    Page 0: header, type|page, LastPageIndex, Length, Timestamp (u32), 17 data bytes.
    Page n: header, type|page, 23 data bytes.
    """
    if len(data) > AUTH_MAX_LENGTH:
        raise ValueError(f"auth data {len(data)} B exceeds {AUTH_MAX_LENGTH} B")
    n = auth_pages_needed(len(data))
    pages = [bytes([_header(MsgType.AUTH), (auth_type << 4) | 0, n - 1, len(data)])
             + struct.pack("<I", odid_ts)
             + data[:AUTH_PAGE0_DATA].ljust(AUTH_PAGE0_DATA, b'\x00')]
    for p in range(1, n):
        off = AUTH_PAGE0_DATA + (p - 1) * AUTH_PAGEN_DATA
        chunk = data[off:off + AUTH_PAGEN_DATA].ljust(AUTH_PAGEN_DATA, b'\x00')
        pages.append(bytes([_header(MsgType.AUTH), (auth_type << 4) | p]) + chunk)
    return pages


def reassemble_auth(pages: List[bytes]) -> Optional[Tuple[int, int, bytes]]:
    """Reassemble Authentication pages into (auth_type, odid_timestamp, data).

    Returns None if pages are missing, inconsistent or malformed.
    """
    by_page = {}
    for b in pages:
        by_page[b[1] & 0x0F] = b
    p0 = by_page.get(0)
    if p0 is None:
        return None
    auth_type, last, length = p0[1] >> 4, p0[2], p0[3]
    if last >= AUTH_MAX_PAGES or len(by_page) != last + 1 or auth_pages_needed(length) != last + 1:
        return None
    if any((by_page[p][1] >> 4) != auth_type for p in by_page):
        return None
    ts = struct.unpack("<I", p0[4:8])[0]
    data = p0[8:25] + b''.join(by_page[p][2:25] for p in range(1, last + 1))
    return auth_type, ts, data[:length]


# --- Message pack (Type 0xF) ------------------------------------------------

def build_message_pack(messages: List[bytes]) -> bytes:
    if not 1 <= len(messages) <= PACK_MAX_MESSAGES:
        raise ValueError(f"message pack holds 1..{PACK_MAX_MESSAGES} messages, got {len(messages)}")
    if any(len(m) != MSG_SIZE for m in messages):
        raise ValueError("all messages must be 25 bytes")
    return bytes([_header(MsgType.PACK), MSG_SIZE, len(messages)]) + b''.join(messages)


def parse_message_pack(data: bytes) -> Optional[List[bytes]]:
    """Split a message pack into its 25-byte messages; None if malformed."""
    if len(data) < 3 or msg_type(data) != MsgType.PACK or data[1] != MSG_SIZE:
        return None
    n = data[2]
    if not 1 <= n <= PACK_MAX_MESSAGES or len(data) < 3 + n * MSG_SIZE:
        return None
    return [data[3 + i * MSG_SIZE: 3 + (i + 1) * MSG_SIZE] for i in range(n)]
