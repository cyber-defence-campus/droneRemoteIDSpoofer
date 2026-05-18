import struct
from datetime import datetime, timedelta
from enum import IntEnum
from typing import Tuple, List

from drone_rid_spoofer.state import DroneState

class MsgType(IntEnum):
    BASIC_ID = 0x0
    LOCATION = 0x1
    AUTH = 0x2
    SELF_ID = 0x3
    SYSTEM = 0x4
    OPERATOR_ID = 0x5
    PACK = 0xF

SELF_ID_DESCRIPTION = b"Spoofing test"


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


def build_basic_id(serial: bytes, protocol_version: int = 2) -> bytes:
    """Build Message Type 0 - Basic ID (25 bytes)."""
    serial_packed = struct.pack("<20s", serial)
    header = bytes([(MsgType.BASIC_ID << 4) | protocol_version, 0x12])
    return header + serial_packed + b'\x00\x00\x00'


def build_location_vector(lat: int, lng: int, direction: int,
                          speed: float = 0.0,
                          vertical_speed: float = 0.0,
                          pressure_altitude: float = 0.0,
                          geodetic_altitude: float = 0.0,
                          height: float = 0.0,
                          timestamp_offset: float = 0.0,
                          protocol_version: int = 2) -> bytes:
    """Build Message Type 1 - Location/Vector (25 bytes).

    Args:
        timestamp_offset: Minutes to shift the ASTM timestamp.
            Negative values produce timestamps in the past.
            The field wraps within the current hour (0-5999 tenth-seconds).
    """
    dir_val, ew_dir = _transform_rotation(direction)
    now = datetime.now() + timedelta(minutes=timestamp_offset)
    tenth_seconds = (now.minute * 600 + now.second * 10) % 6000

    return b''.join([
        struct.pack("<B", (MsgType.LOCATION << 4) | protocol_version),
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


def build_system(pilot_lat: int, pilot_lng: int, protocol_version: int = 2) -> bytes:
    """Build Message Type 4 - System (25 bytes)."""
    return b''.join([
        struct.pack("<B", (MsgType.SYSTEM << 4) | protocol_version),
        struct.pack("<B", 0x05),
        struct.pack("<i", pilot_lat),
        struct.pack("<i", pilot_lng),
        b'\x00\x00\x00\x00\x00\x00\x00',
        struct.pack("<B", 0x12),
        b'\x00\x00\x00\x00\x00\x00\x00'
    ])


def build_self_id(description: bytes = SELF_ID_DESCRIPTION, protocol_version: int = 2) -> bytes:
    """Build Message Type 3 - Self ID (25 bytes).

    Description type 0x00 = text. Body is 23 ASCII bytes (null-padded).
    """
    body = description[:23].ljust(23, b'\x00')
    header = bytes([(MsgType.SELF_ID << 4) | protocol_version, 0x00])
    return header + body


def build_operator_id(protocol_version: int = 2) -> bytes:
    """Build Message Type 5 - Operator ID (25 bytes)."""
    return bytes([(MsgType.OPERATOR_ID << 4) | protocol_version]) + b'\x00' * 24


def build_all_messages(drone: DroneState, protocol_version: int = 2) -> List[bytes]:
    """Build all ASTM message payloads for a drone."""
    return [
        build_basic_id(drone.serial, protocol_version=protocol_version),
        build_location_vector(
            drone.lat, drone.lng, drone.direction,
            speed=drone.speed,
            vertical_speed=drone.vertical_speed,
            pressure_altitude=drone.pressure_altitude,
            geodetic_altitude=drone.geodetic_altitude,
            height=drone.height,
            timestamp_offset=drone.timestamp_offset,
            protocol_version=protocol_version
        ),
        build_self_id(protocol_version=protocol_version),
        build_system(drone.pilot_location[0], drone.pilot_location[1], protocol_version=protocol_version),
        build_operator_id(protocol_version=protocol_version),
    ]
