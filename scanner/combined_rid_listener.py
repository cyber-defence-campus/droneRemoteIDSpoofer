#!/usr/bin/env python3
"""
Combined Bluetooth (nRF UART) and Wi-Fi Drone Remote ID (RID) Listener & Logger
Compliant with ASTM F3411-19 / ASTM F3411-22 / ASD-STAN OpenDroneID standards.

Architecture:
- Thread 1: BLE Sniffer Thread (runs nrf_bt_sniffer_json.py over UART for BLE 4/5 RID packets)
- Thread 2: Wi-Fi Channel Hopper Thread (executes multi-band 2.4 GHz / 5.8 GHz hopping schedule)
- Thread 3: Wi-Fi Sniffer Thread (AF_PACKET raw socket capturing Beacons & NAN Action Frames)
- Logging Pipeline:
    1. Real-time formatted console display with colorized telemetry.
    2. Replay-compatible append-only JSONL log (direct drop-in for replay_drones.py).
    3. SQLite database for 5-minute (300s) aggregated Flight Encounters & trajectory tracking.
"""

import argparse
import base64
import json
import logging
import os
import queue
import select
import signal
import socket
import sqlite3
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# ANSI Terminal Colors
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN = "\033[96m"
C_WHITE = "\033[97m"
C_GRAY = "\033[90m"

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("CombinedRIDListener")


# ============================================================================
# ASTM F3411 Protocol Constants & Comprehensive Enum Lookup Tables
# ============================================================================

ASTM_OUI = b"\xfa\x0b\xbc"      # OpenDroneID / ASTM OUI in Wi-Fi Vendor IE
APP_CODE_RID = 0x0D             # Application Code for Drone Remote ID
BLE_RID_UUID = b"\xfa\xff"      # 16-bit UUID 0xFFFA (Little-Endian)
OPENDRONEID_EPOCH_2019 = 1546300800  # 2019-01-01 00:00:00 UTC Unix Epoch

MSG_TYPE_NAMES = {
    0x0: "Basic ID",
    0x1: "Location",
    0x2: "Auth",
    0x3: "Self-ID",
    0x4: "System",
    0x5: "Operator ID",
    0xF: "Message Pack",
}

PROTO_VERSION_NAMES = {
    0: "ASTM F3411-19 (v0)",
    1: "ASD-STAN prEN 4709-002 (v1)",
    2: "ASTM F3411-22 (v2)",
}

ID_TYPE_NAMES = {
    0: "None",
    1: "Serial Number (ANSI/CTA-2063-A)",
    2: "CAA Registration ID",
    3: "UTM Assigned UUID",
    4: "Specific Session ID (ICAO Managed / Private)",
}

UA_TYPE_NAMES = {
    0: "None",
    1: "Aeroplane (Fixed Wing)",
    2: "Helicopter / Multirotor",
    3: "Gyroplane",
    4: "Hybrid Lift (VTOL)",
    5: "Ornithopter",
    6: "Glider",
    7: "Kite",
    8: "Free Balloon",
    9: "Captive Balloon",
    10: "Airship (Blimp)",
    11: "Free Fall Parachute",
    12: "Rocket",
    13: "Tethered Powered Aircraft",
    14: "Ground Obstacle",
    15: "Other",
}

STATUS_NAMES = {
    0: "Undeclared",
    1: "Ground",
    2: "Airborne",
    3: "Emergency",
    4: "Remote ID System Failure (v2)",
}

HEIGHT_TYPE_NAMES = {
    0: "Above Takeoff",
    1: "Above Ground Level (AGL)",
}

HORIZ_ACCURACY_NAMES = {
    0: "Unknown",
    1: "< 10 NM (18.52 km)",
    2: "< 4 NM (7.408 km)",
    3: "< 2 NM (3.704 km)",
    4: "< 1 NM (1.852 km)",
    5: "< 0.5 NM (926 m)",
    6: "< 0.3 NM (555.6 m)",
    7: "< 0.1 NM (185.2 m)",
    8: "< 0.05 NM (92.6 m)",
    9: "< 30 m",
    10: "< 10 m",
    11: "< 3 m",
    12: "< 1 m",
}

VERT_ACCURACY_NAMES = {
    0: "Unknown",
    1: "> 150 m",
    2: "< 150 m",
    3: "< 45 m",
    4: "< 25 m",
    5: "< 10 m",
    6: "< 3 m",
    7: "< 1 m",
}

SPEED_ACCURACY_NAMES = {
    0: "Unknown",
    1: "< 10 m/s",
    2: "< 3 m/s",
    3: "< 1 m/s",
    4: "< 0.3 m/s",
}

TIMESTAMP_ACCURACY_NAMES = {
    0: "Unknown",
    **{i: f"< {i*0.1:.1f} s" for i in range(1, 16)}
}

AUTH_TYPE_NAMES = {
    0: "None",
    1: "UAS ID Signature",
    2: "Operator ID Signature",
    3: "Message Set Signature",
    4: "Network Remote ID",
    5: "Specific Authentication (ICAO / Private)",
}

DESC_TYPE_NAMES = {
    0: "Text",
    1: "Emergency Status (v2)",
    2: "Extended Status (v2)",
}

OPERATOR_LOCATION_TYPE_NAMES = {
    0: "Takeoff Location",
    1: "Live GNSS (Dynamic Pilot / GCS)",
    2: "Fixed Location",
}

CLASSIFICATION_TYPE_NAMES = {
    0: "Undeclared",
    1: "European Union (EU)",
}

EU_CATEGORY_NAMES = {
    0: "Undeclared",
    1: "Open",
    2: "Specific",
    3: "Certified",
}

EU_CLASS_NAMES = {
    0: "Undeclared",
    1: "Class 0",
    2: "Class 1",
    3: "Class 2",
    4: "Class 3",
    5: "Class 4",
    6: "Class 5",
    7: "Class 6",
}


def sanitize_ascii_string(raw: bytes, max_len: int = 25) -> str:
    """
    Sanitize untrusted over-the-air ASCII string bytes:
    1. Truncates at first null byte (0x00).
    2. Strips all non-printable ASCII control characters (0x00-0x1F, 0x7F, ANSI ESC \x1b)
       to prevent terminal escape injection (DA-03).
    3. Retains only safe printable characters (0x20 to 0x7E).
    """
    cleaned = []
    for b in raw[:max_len]:
        if b == 0:
            break
        if 0x20 <= b <= 0x7E:
            cleaned.append(chr(b))
        else:
            cleaned.append('?')  # Replace non-printable / control codes
    return ''.join(cleaned).strip()


def decode_astm_message(block: bytes) -> Optional[Dict[str, Any]]:
    """
    Decode a single 25-byte ASTM F3411 / OpenDroneID message block with full subparts,
    accurate scaling formulas, human-readable enums, and protocol version metadata.
    """
    if len(block) < 25:
        return None

    header = block[0]
    msg_type = (header >> 4) & 0x0F
    proto_ver = header & 0x0F

    result: Dict[str, Any] = {
        "type": MSG_TYPE_NAMES.get(msg_type, f"Unknown (0x{msg_type:X})"),
        "type_id": msg_type,
        "proto_version": proto_ver,
        "proto_version_name": PROTO_VERSION_NAMES.get(proto_ver, f"Reserved (v{proto_ver})"),
        "raw_hex": block[:25].hex().upper(),
        "raw_b64": base64.b64encode(block[:25]).decode('ascii')
    }

    try:
        if msg_type == 0x0:  # Basic ID (Type 0)
            id_type_raw = block[1]
            id_type = (id_type_raw >> 4) & 0x0F
            ua_type = id_type_raw & 0x0F
            uas_id = sanitize_ascii_string(block[2:22], max_len=20)
            result.update({
                "id": uas_id,
                "id_type": id_type,
                "id_type_name": ID_TYPE_NAMES.get(id_type, f"Reserved ({id_type})"),
                "ua_type": ua_type,
                "ua_type_name": UA_TYPE_NAMES.get(ua_type, f"Reserved ({ua_type})"),
            })

        elif msg_type == 0x1:  # Location / Vector (Type 1)
            b1 = block[1]
            status = (b1 >> 4) & 0x0F
            height_type = (b1 >> 2) & 0x01
            ew_dir = (b1 >> 1) & 0x01
            speed_mult = b1 & 0x01

            dir_raw = block[2]
            direction_deg = dir_raw + 180 if ew_dir else dir_raw
            if direction_deg > 360:
                direction_deg = None  # 361 = Invalid / Unknown

            speed_raw = block[3]
            if speed_raw == 255 and speed_mult == 0:
                speed_mps = None
            else:
                speed_mps = (speed_raw * 0.25) if speed_mult == 0 else (63.75 + speed_raw * 0.75)

            v_speed_raw = struct.unpack('<b', block[4:5])[0]
            if v_speed_raw == 63:
                v_speed_mps = None
            else:
                v_speed_mps = v_speed_raw * 0.5

            lat_raw = struct.unpack('<i', block[5:9])[0]
            lon_raw = struct.unpack('<i', block[9:13])[0]
            lat = (lat_raw / 1e7) if (lat_raw != 0 or lon_raw != 0) else None
            lon = (lon_raw / 1e7) if (lat_raw != 0 or lon_raw != 0) else None

            p_alt_raw = struct.unpack('<H', block[13:15])[0]
            p_alt_m = (p_alt_raw * 0.5 - 1000.0) if p_alt_raw != 0 else None

            g_alt_raw = struct.unpack('<H', block[15:17])[0]
            g_alt_m = (g_alt_raw * 0.5 - 1000.0) if g_alt_raw != 0 else None

            height_raw = struct.unpack('<H', block[17:19])[0]
            height_m = (height_raw * 0.5 - 1000.0) if height_raw != 0 else None

            b19 = block[19]
            vert_acc = (b19 >> 4) & 0x0F
            horiz_acc = b19 & 0x0F

            b20 = block[20]
            baro_acc = (b20 >> 4) & 0x0F
            speed_acc = b20 & 0x0F

            ts_raw = struct.unpack('<H', block[21:23])[0]
            timestamp_s = (ts_raw / 10.0) if ts_raw != 0xFFFF else None

            b23 = block[23]
            ts_acc = b23 & 0x0F

            result.update({
                "status": status,
                "status_name": STATUS_NAMES.get(status, f"Reserved ({status})"),
                "direction_deg": direction_deg,
                "speed_mps": round(speed_mps, 2) if speed_mps is not None else None,
                "speed_multiplier": speed_mult,
                "vertical_speed_mps": round(v_speed_mps, 2) if v_speed_mps is not None else None,
                "lat": lat,
                "lon": lon,
                "pressure_altitude_m": round(p_alt_m, 2) if p_alt_m is not None else None,
                "geodetic_altitude_m": round(g_alt_m, 2) if g_alt_m is not None else None,
                "height_m": round(height_m, 2) if height_m is not None else None,
                "height_type": height_type,
                "height_type_name": HEIGHT_TYPE_NAMES.get(height_type, "Unknown"),
                "horizontal_accuracy": horiz_acc,
                "horizontal_accuracy_name": HORIZ_ACCURACY_NAMES.get(horiz_acc, "Unknown"),
                "vertical_accuracy": vert_acc,
                "vertical_accuracy_name": VERT_ACCURACY_NAMES.get(vert_acc, "Unknown"),
                "baro_accuracy": baro_acc,
                "baro_accuracy_name": VERT_ACCURACY_NAMES.get(baro_acc, "Unknown"),
                "speed_accuracy": speed_acc,
                "speed_accuracy_name": SPEED_ACCURACY_NAMES.get(speed_acc, "Unknown"),
                "timestamp_s": timestamp_s,
                "timestamp_accuracy": ts_acc,
                "timestamp_accuracy_name": TIMESTAMP_ACCURACY_NAMES.get(ts_acc, "Unknown"),
            })

        elif msg_type == 0x2:  # Auth (Type 2)
            b1 = block[1]
            auth_type = (b1 >> 4) & 0x0F
            page_num = b1 & 0x0F

            result.update({
                "auth_type": auth_type,
                "auth_type_name": AUTH_TYPE_NAMES.get(auth_type, f"Reserved ({auth_type})"),
                "page_number": page_num,
            })

            if page_num == 0:
                last_page_idx = block[2]
                length = block[3]
                ts_raw = struct.unpack('<I', block[4:8])[0]
                auth_ts_epoch = (OPENDRONEID_EPOCH_2019 + ts_raw) if ts_raw > 0 else None
                auth_ts_iso = datetime.fromtimestamp(auth_ts_epoch, timezone.utc).isoformat() if auth_ts_epoch else None
                auth_data_hex = block[8:25].hex().upper()

                result.update({
                    "last_page_index": last_page_idx,
                    "auth_data_length": length,
                    "auth_timestamp_epoch": auth_ts_epoch,
                    "auth_timestamp_iso": auth_ts_iso,
                    "auth_data_hex": auth_data_hex,
                })
            else:
                auth_data_hex = block[2:25].hex().upper()
                result.update({
                    "auth_data_hex": auth_data_hex,
                })

        elif msg_type == 0x3:  # Self-ID (Type 3)
            desc_type = block[1]
            desc = sanitize_ascii_string(block[2:25], max_len=23)
            result.update({
                "desc_type": desc_type,
                "desc_type_name": DESC_TYPE_NAMES.get(desc_type, f"Reserved ({desc_type})"),
                "description": desc,
            })

        elif msg_type == 0x4:  # System (Type 4)
            b1 = block[1]
            op_loc_type = b1 & 0x03
            class_type = (b1 >> 2) & 0x07

            op_lat_raw = struct.unpack('<i', block[2:6])[0]
            op_lon_raw = struct.unpack('<i', block[6:10])[0]
            pilot_lat = (op_lat_raw / 1e7) if (op_lat_raw != 0 or op_lon_raw != 0) else None
            pilot_lon = (op_lon_raw / 1e7) if (op_lat_raw != 0 or op_lon_raw != 0) else None

            area_count = struct.unpack('<H', block[10:12])[0]
            area_radius = block[12] * 10

            area_ceil_raw = struct.unpack('<H', block[13:15])[0]
            area_ceil_m = (area_ceil_raw * 0.5 - 1000.0) if area_ceil_raw != 0 else None

            area_floor_raw = struct.unpack('<H', block[15:17])[0]
            area_floor_m = (area_floor_raw * 0.5 - 1000.0) if area_floor_raw != 0 else None

            b17 = block[17]
            category_eu = (b17 >> 4) & 0x0F
            class_eu = b17 & 0x0F

            op_alt_raw = struct.unpack('<H', block[18:20])[0]
            pilot_alt_m = (op_alt_raw * 0.5 - 1000.0) if op_alt_raw != 0 else None

            sys_ts_raw = struct.unpack('<I', block[20:24])[0]
            sys_ts_epoch = (OPENDRONEID_EPOCH_2019 + sys_ts_raw) if sys_ts_raw > 0 else None
            sys_ts_iso = datetime.fromtimestamp(sys_ts_epoch, timezone.utc).isoformat() if sys_ts_epoch else None

            result.update({
                "operator_location_type": op_loc_type,
                "operator_location_type_name": OPERATOR_LOCATION_TYPE_NAMES.get(op_loc_type, "Reserved"),
                "classification_type": class_type,
                "classification_type_name": CLASSIFICATION_TYPE_NAMES.get(class_type, f"Reserved ({class_type})"),
                "pilot_lat": pilot_lat,
                "pilot_lon": pilot_lon,
                "area_count": area_count,
                "area_radius_m": area_radius,
                "area_ceiling_m": area_ceil_m,
                "area_floor_m": area_floor_m,
                "category_eu": category_eu,
                "category_eu_name": EU_CATEGORY_NAMES.get(category_eu, f"Reserved ({category_eu})"),
                "class_eu": class_eu,
                "class_eu_name": EU_CLASS_NAMES.get(class_eu, f"Reserved ({class_eu})"),
                "pilot_alt_m": pilot_alt_m,
                "system_timestamp_epoch": sys_ts_epoch,
                "system_timestamp_iso": sys_ts_iso,
            })

        elif msg_type == 0x5:  # Operator ID (Type 5)
            op_id_type = block[1]
            op_id = sanitize_ascii_string(block[2:22], max_len=20)
            result.update({
                "operator_id_type": op_id_type,
                "operator_id_type_name": "Operator ID" if op_id_type == 0 else f"Reserved ({op_id_type})",
                "operator_id": op_id,
            })

    except Exception as e:
        result["parse_error"] = str(e)

    return result


def parse_astm_payload(payload: bytes) -> Tuple[List[Dict[str, Any]], List[str]]:
    """
    Parse ASTM F3411 payload bytes with strict bounds and dimensions validation.
    Hardened against:
      - DA-01: Zero-length / malformed message packs & recursive sub-packs
      - RDBP-02: Buffer over-read on truncated packet frames
    Returns:
      - results: List of decoded message dicts
      - raw_b64_blocks: List of 25-byte base64-encoded strings (for replay_drones.py)
    """
    results = []
    raw_b64_blocks = []
    i = 0
    total_len = len(payload)

    while i < total_len:
        if i >= total_len:
            break

        header = payload[i]
        msg_type = (header >> 4) & 0x0F

        if msg_type == 0xF:  # Message Pack
            # Validate pack header structure: at least 3 bytes (Header, SingleMessageSize, MsgPackSize)
            if i + 3 > total_len:
                break

            msg_size = payload[i + 1]
            msg_count = payload[i + 2]

            # ASTM F3411 Specification: msg_size MUST be 25 (0x19) and msg_count MUST be 1..9
            if msg_size != 25 or msg_count == 0 or msg_count > 9:
                # Malformed pack header -> terminate parsing to prevent index desynchronization
                break

            expected_pack_bytes = 3 + (msg_count * 25)
            if i + expected_pack_bytes > total_len:
                # Truncated pack payload -> do not process partial/corrupted pack
                break

            i += 3
            for _ in range(msg_count):
                chunk = payload[i : i + 25]
                # Reject nested / recursive message packs (DA-01)
                sub_msg_type = (chunk[0] >> 4) & 0x0F
                if sub_msg_type != 0xF:
                    decoded = decode_astm_message(chunk)
                    if decoded:
                        results.append(decoded)
                    raw_b64_blocks.append(base64.b64encode(chunk).decode('ascii'))
                i += 25

        else:  # Single message block
            if i + 25 <= total_len:
                chunk = payload[i : i + 25]
                decoded = decode_astm_message(chunk)
                if decoded:
                    results.append(decoded)
                raw_b64_blocks.append(base64.b64encode(chunk).decode('ascii'))
                i += 25
            else:
                # Trailing bytes < 25 bytes cannot form a valid message
                break

    return results, raw_b64_blocks


# ============================================================================
# Wi-Fi Channel State & Hopping Definitions
# ============================================================================

SOCIAL_CHANNEL_2G = 6
NON_SOCIAL_CHANNELS_2G = [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13]

SOCIAL_CHANNEL_5G = 149
NON_SOCIAL_CHANNELS_5G = [153, 157, 161, 165, 169, 173]


def get_band_for_channel(ch: int) -> str:
    if ch <= 14:
        return "2.4GHz"
    elif ch >= 36:
        return "5.8GHz" if ch >= 149 else "5GHz"
    return "Unknown"


def get_freq_for_channel(ch: int) -> int:
    if ch == 14:
        return 2484
    elif 1 <= ch <= 13:
        return 2407 + 5 * ch
    elif ch >= 36:
        return 5000 + 5 * ch
    return 0


class SharedChannelState:
    """Thread-safe state holding the current active Wi-Fi channel and band."""
    def __init__(self, initial_channel: int = 6):
        self.lock = threading.Lock()
        self.channel = initial_channel
        self.band = get_band_for_channel(initial_channel)
        self.frequency = get_freq_for_channel(initial_channel)
        self.last_switch_time = time.time()
        self.total_switches = 0

    def update(self, new_channel: int):
        with self.lock:
            self.channel = new_channel
            self.band = get_band_for_channel(new_channel)
            self.frequency = get_freq_for_channel(new_channel)
            self.last_switch_time = time.time()
            self.total_switches += 1

    def get(self) -> Tuple[int, str, int, float]:
        with self.lock:
            return self.channel, self.band, self.frequency, self.last_switch_time


# ============================================================================
# SQLite Encounter Database Manager
# ============================================================================

class EncounterTracker:
    """
    Groups individual Remote ID packets into 5-minute (300s) Flight Encounters
    and commits completed/updated encounters into an SQLite database.
    """
    def __init__(self, db_path: Optional[str] = "rid_detections.db", timeout_s: float = 300.0):
        self.db_path = db_path
        self.timeout_s = timeout_s
        self.active_encounters: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()

        if self.db_path:
            self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA synchronous = NORMAL;")
            conn.execute("""
                CREATE TABLE IF NOT EXISTS encounters (
                    encounter_id TEXT PRIMARY KEY,
                    mac TEXT NOT NULL,
                    serial_number TEXT,
                    first_seen REAL NOT NULL,
                    first_seen_iso TEXT NOT NULL,
                    last_seen REAL NOT NULL,
                    last_seen_iso TEXT NOT NULL,
                    duration_s REAL NOT NULL,
                    packet_count INTEGER NOT NULL,
                    transports TEXT NOT NULL,
                    channels TEXT NOT NULL,
                    min_rssi_dbm INTEGER,
                    max_rssi_dbm INTEGER,
                    avg_rssi_dbm REAL,
                    min_alt_m REAL,
                    max_alt_m REAL,
                    max_speed_mps REAL,
                    pilot_lat REAL,
                    pilot_lon REAL,
                    pilot_alt_m REAL,
                    operator_id TEXT,
                    self_id_desc TEXT,
                    trajectory_json TEXT,
                    is_active INTEGER NOT NULL DEFAULT 1
                );
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_encounters_mac ON encounters(mac);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_encounters_serial ON encounters(serial_number);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_encounters_time ON encounters(first_seen, last_seen);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_encounters_active ON encounters(is_active);")
            conn.commit()

    def update_with_packet(self, packet: Dict[str, Any]) -> str:
        """Update or create an active encounter from an incoming packet. Returns encounter_id."""
        mac = packet.get("mac", "UNKNOWN")
        serial = packet.get("serial_number")
        ts = packet.get("timestamp", time.time())
        transport = packet.get("transport", "unknown")
        ch_str = str(packet.get("channel", "N/A"))
        rssi = packet.get("rssi_dbm")

        key = f"{mac}_{serial}" if serial else mac
        now = time.time()

        with self.lock:
            # Check if existing encounter timed out (> 5 minutes)
            if key in self.active_encounters:
                enc = self.active_encounters[key]
                if ts - enc["last_seen"] > self.timeout_s:
                    # Finalize old encounter
                    enc["is_active"] = 0
                    self._persist_encounter(enc)
                    del self.active_encounters[key]

            if key not in self.active_encounters:
                # Generate unique encounter ID
                enc_slug = mac.replace(":", "")[-6:]
                dt_tag = datetime.fromtimestamp(ts, timezone.utc).strftime("%Y%m%d-%H%M%S")
                encounter_id = f"ENC-{dt_tag}-{enc_slug}"

                self.active_encounters[key] = {
                    "encounter_id": encounter_id,
                    "mac": mac,
                    "serial_number": serial,
                    "first_seen": ts,
                    "first_seen_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                    "last_seen": ts,
                    "last_seen_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                    "duration_s": 0.0,
                    "packet_count": 0,
                    "transports": set([transport]),
                    "channels": set([ch_str]),
                    "rssi_values": [rssi] if rssi is not None else [],
                    "altitudes": [],
                    "speeds": [],
                    "pilot_lat": None,
                    "pilot_lon": None,
                    "pilot_alt_m": None,
                    "operator_id": None,
                    "self_id_desc": None,
                    "trajectory": [],
                    "is_active": 1,
                }

            enc = self.active_encounters[key]
            enc["last_seen"] = ts
            enc["last_seen_iso"] = datetime.fromtimestamp(ts, timezone.utc).isoformat()
            enc["duration_s"] = round(enc["last_seen"] - enc["first_seen"], 2)
            enc["packet_count"] += 1
            enc["transports"].add(transport)
            enc["channels"].add(ch_str)
            if serial and not enc["serial_number"]:
                enc["serial_number"] = serial

            if rssi is not None:
                enc["rssi_values"].append(rssi)

            # Parse message telemetry fields
            for msg in packet.get("messages", []):
                m_type = msg.get("type")
                if m_type == "Location":
                    lat = msg.get("lat")
                    lon = msg.get("lon")
                    alt = msg.get("geodetic_altitude_m") or msg.get("pressure_altitude_m")
                    spd = msg.get("speed_mps")
                    heading = msg.get("direction_deg")
                    if alt is not None:
                        enc["altitudes"].append(alt)
                    if spd is not None:
                        enc["speeds"].append(spd)
                    if lat is not None and lon is not None:
                        # Append trajectory coordinate tuple [lat, lon, alt, speed, heading, ts]
                        enc["trajectory"].append([lat, lon, alt, spd, heading, round(ts, 2)])

                elif m_type == "Basic ID":
                    if msg.get("id") and not enc.get("serial_number"):
                        enc["serial_number"] = msg.get("id")

                elif m_type == "System":
                    if msg.get("pilot_lat") is not None:
                        enc["pilot_lat"] = msg.get("pilot_lat")
                    if msg.get("pilot_lon") is not None:
                        enc["pilot_lon"] = msg.get("pilot_lon")
                    if msg.get("pilot_alt_m") is not None:
                        enc["pilot_alt_m"] = msg.get("pilot_alt_m")

                elif m_type == "Operator ID":
                    if msg.get("operator_id"):
                        enc["operator_id"] = msg.get("operator_id")

                elif m_type == "Self-ID":
                    if msg.get("description"):
                        enc["self_id_desc"] = msg.get("description")

            # Persist live progress
            self._persist_encounter(enc)
            return enc["encounter_id"]

    def check_timeouts(self, now: Optional[float] = None) -> List[str]:
        """Check for and close any encounters that have been silent for > timeout_s."""
        if now is None:
            now = time.time()
        closed_ids = []
        with self.lock:
            keys_to_delete = []
            for key, enc in self.active_encounters.items():
                if now - enc["last_seen"] > self.timeout_s:
                    enc["is_active"] = 0
                    self._persist_encounter(enc)
                    closed_ids.append(enc["encounter_id"])
                    keys_to_delete.append(key)
            for k in keys_to_delete:
                del self.active_encounters[k]
        return closed_ids

    def finalize_all(self):
        """Mark all active encounters as completed on shutdown."""
        with self.lock:
            for enc in self.active_encounters.values():
                enc["is_active"] = 0
                self._persist_encounter(enc)
            self.active_encounters.clear()

    def _persist_encounter(self, enc: Dict[str, Any]):
        if not self.db_path:
            return

        rssi_vals = enc["rssi_values"]
        min_rssi = min(rssi_vals) if rssi_vals else None
        max_rssi = max(rssi_vals) if rssi_vals else None
        avg_rssi = round(sum(rssi_vals) / len(rssi_vals), 1) if rssi_vals else None

        alts = enc["altitudes"]
        min_alt = min(alts) if alts else None
        max_alt = max(alts) if alts else None

        speeds = enc["speeds"]
        max_speed = max(speeds) if speeds else None

        transports_str = ",".join(sorted(enc["transports"]))
        channels_str = ",".join(sorted(enc["channels"]))
        trajectory_str = json.dumps(enc["trajectory"])

        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    INSERT OR REPLACE INTO encounters (
                        encounter_id, mac, serial_number, first_seen, first_seen_iso,
                        last_seen, last_seen_iso, duration_s, packet_count, transports,
                        channels, min_rssi_dbm, max_rssi_dbm, avg_rssi_dbm, min_alt_m,
                        max_alt_m, max_speed_mps, pilot_lat, pilot_lon, pilot_alt_m,
                        operator_id, self_id_desc, trajectory_json, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    enc["encounter_id"],
                    enc["mac"],
                    enc["serial_number"],
                    enc["first_seen"],
                    enc["first_seen_iso"],
                    enc["last_seen"],
                    enc["last_seen_iso"],
                    enc["duration_s"],
                    enc["packet_count"],
                    transports_str,
                    channels_str,
                    min_rssi,
                    max_rssi,
                    avg_rssi,
                    min_alt,
                    max_alt,
                    max_speed,
                    enc["pilot_lat"],
                    enc["pilot_lon"],
                    enc["pilot_alt_m"],
                    enc["operator_id"],
                    enc["self_id_desc"],
                    trajectory_str,
                    enc["is_active"]
                ))
                conn.commit()
        except Exception as e:
            logger.debug(f"Error persisting encounter to SQLite: {e}")


# ============================================================================
# Thread 1: Wi-Fi Channel Hopper Thread
# ============================================================================

class WifiChannelHopperThread(threading.Thread):
    """
    Dedicated thread executing the Wi-Fi Remote ID channel hopping schedule:
    - 2.4 GHz Social Channel: Ch 6 (1000 ms dwell)
    - 2.4 GHz Non-Social Channels: (200 ms dwell each, 30 ms intraband switch)
    - 5.8 GHz Social Channel: Ch 149 (1000 ms dwell, 50 ms interband switch)
    - 5.8 GHz Non-Social Channels: (200 ms dwell each, 30 ms intraband switch)
    - Configurable non-social ratio (2k on 2.4GHz for every k on 5.8GHz)
    """
    def __init__(
        self,
        interface: str,
        channel_state: SharedChannelState,
        non_social_ratio_k: int = 1,
        social_dwell_ms: int = 1000,
        non_social_dwell_ms: int = 200,
        intraband_delay_ms: int = 30,
        interband_delay_ms: int = 50,
    ):
        super().__init__(name="WifiHopperThread", daemon=True)
        self.interface = interface
        self.channel_state = channel_state
        self.k = max(1, non_social_ratio_k)
        self.social_dwell_s = social_dwell_ms / 1000.0
        self.non_social_dwell_s = non_social_dwell_ms / 1000.0
        self.intraband_delay_s = intraband_delay_ms / 1000.0
        self.interband_delay_s = interband_delay_ms / 1000.0
        self.running = False
        self.current_channel = 6

        self.n_2g_non_social = 2 * self.k
        self.n_5g_non_social = self.k

        self.idx_2g = 0
        self.idx_5g = 0

    def _set_channel(self, channel: int):
        cmd = ["iw", "dev", self.interface, "set", "channel", str(channel)]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception as e:
            logger.debug(f"Error executing iw command: {e}")

    def _hop_step(self, target_channel: int, dwell_time: float, switch_delay: float):
        if not self.running:
            return

        if switch_delay > 0:
            time.sleep(switch_delay)

        if not self.running:
            return

        self._set_channel(target_channel)
        self.current_channel = target_channel
        self.channel_state.update(target_channel)
        time.sleep(dwell_time)

    def run(self):
        self.running = True
        logger.info(
            f"[*] Wi-Fi Hopper started on {self.interface} "
            f"(2.4G Non-Social: {self.n_2g_non_social}/cycle, 5.8G Non-Social: {self.n_5g_non_social}/cycle, "
            f"Social Dwell: {self.social_dwell_s*1000:.0f}ms, Non-Social Dwell: {self.non_social_dwell_s*1000:.0f}ms)"
        )

        self._set_channel(SOCIAL_CHANNEL_2G)
        self.channel_state.update(SOCIAL_CHANNEL_2G)

        try:
            while self.running:
                # --- Step 1: 2.4 GHz Social Channel (Ch 6) ---
                self._hop_step(SOCIAL_CHANNEL_2G, self.social_dwell_s, self.interband_delay_s)

                # --- Step 2: 2.4 GHz Non-Social Channels (2k channels) ---
                for _ in range(self.n_2g_non_social):
                    if not self.running:
                        break
                    ch_2g = NON_SOCIAL_CHANNELS_2G[self.idx_2g % len(NON_SOCIAL_CHANNELS_2G)]
                    self.idx_2g += 1
                    self._hop_step(ch_2g, self.non_social_dwell_s, self.intraband_delay_s)

                # --- Step 3: 5.8 GHz Social Channel (Ch 149) ---
                self._hop_step(SOCIAL_CHANNEL_5G, self.social_dwell_s, self.interband_delay_s)

                # --- Step 4: 5.8 GHz Non-Social Channels (k channels) ---
                for _ in range(self.n_5g_non_social):
                    if not self.running:
                        break
                    ch_5g = NON_SOCIAL_CHANNELS_5G[self.idx_5g % len(NON_SOCIAL_CHANNELS_5G)]
                    self.idx_5g += 1
                    self._hop_step(ch_5g, self.non_social_dwell_s, self.intraband_delay_s)

        except Exception as e:
            if self.running:
                logger.error(f"[-] Wi-Fi Hopper encountered error: {e}")
        finally:
            self.running = False
            logger.info("[*] Wi-Fi Channel Hopper stopped.")

    def stop(self):
        self.running = False


# ============================================================================
# Thread 2: Wi-Fi Sniffer & Frame Parser Thread
# ============================================================================

class WifiSnifferThread(threading.Thread):
    """
    Captures raw 802.11 frames on monitor-mode interface using AF_PACKET raw socket.
    Parses Wi-Fi Beacon Vendor Specific Elements (FA:0B:BC) and NAN Action frames.
    """
    def __init__(
        self,
        interface: str,
        channel_state: SharedChannelState,
        event_queue: queue.Queue,
    ):
        super().__init__(name="WifiSnifferThread", daemon=True)
        self.interface = interface
        self.channel_state = channel_state
        self.event_queue = event_queue
        self.running = False
        self.sock: Optional[socket.socket] = None

    def run(self):
        self.running = True
        logger.info(f"[*] Starting Wi-Fi Sniffer on {self.interface}...")

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((self.interface, 0))
        except Exception as e:
            logger.error(f"[-] Failed to bind AF_PACKET raw socket on {self.interface}: {e}. (Need root / sudo)")
            self.running = False
            return

        while self.running:
            try:
                ready = select.select([self.sock], [], [], 0.1)
                if not ready[0]:
                    continue

                frame = self.sock.recv(4096)
                if len(frame) < 24:
                    continue

                ts = time.time()
                cur_ch, cur_band, cur_freq, _ = self.channel_state.get()

                # Fast check for ASTM OUI (FA:0B:BC) or NAN Action frames
                oui_idx = frame.find(ASTM_OUI)
                is_nan = False

                if oui_idx == -1:
                    radiotap_len = struct.unpack('<H', frame[2:4])[0] if len(frame) >= 4 else 0
                    if len(frame) > radiotap_len + 2:
                        fc = frame[radiotap_len]
                        if fc in (0xD0, 0xE0):
                            for offset in range(radiotap_len + 24, min(len(frame) - 4, radiotap_len + 128)):
                                if (frame[offset] >> 4) == 0xF and frame[offset + 1] == 0x19:
                                    is_nan = True
                                    oui_idx = offset - 3
                                    break
                    if not is_nan:
                        continue

                radiotap_len = struct.unpack('<H', frame[2:4])[0] if len(frame) >= 4 else 0
                if len(frame) < radiotap_len + 24:
                    continue

                # Extract MAC Address (addr2 / transmitter address)
                mac_bytes = frame[radiotap_len + 10 : radiotap_len + 16]
                mac_addr = ':'.join(f'{b:02X}' for b in mac_bytes)

                # Extract RSSI if Radiotap signal field is available
                rssi_dbm = None
                if radiotap_len >= 8:
                    try:
                        present_flags = struct.unpack('<I', frame[4:8])[0]
                        if present_flags & 0x00000020:
                            for b_idx in range(8, min(radiotap_len, 32)):
                                val = struct.unpack('<b', frame[b_idx:b_idx+1])[0]
                                if -100 <= val <= -10:
                                    rssi_dbm = val
                                    break
                    except Exception:
                        pass

                # Extract Payload
                counter = 0
                if is_nan:
                    transport = "nan"
                    nan_body = frame[radiotap_len + 24:]
                    pack_idx = -1
                    for k in range(len(nan_body) - 3):
                        if (nan_body[k] >> 4) == 0xF and nan_body[k+1] == 0x19:
                            pack_idx = k
                            break
                    if pack_idx != -1:
                        astm_payload = nan_body[pack_idx:]
                    else:
                        continue
                else:
                    transport = "wifi"
                    if oui_idx < 2 or frame[oui_idx - 2] != 0xDD:
                        continue
                    ie_len = frame[oui_idx - 1]
                    if oui_idx + ie_len - 1 > len(frame):
                        continue
                    vendor_data = frame[oui_idx + 3 : oui_idx - 1 + ie_len]
                    if len(vendor_data) < 2 or vendor_data[0] != APP_CODE_RID:
                        continue
                    counter = vendor_data[1] if len(vendor_data) > 1 else 0
                    astm_payload = vendor_data[2:]

                # Decode ASTM Messages and raw 25-byte blocks
                parsed_messages, messages_b64 = parse_astm_payload(astm_payload)
                if not parsed_messages:
                    continue

                serial_no = None
                for msg in parsed_messages:
                    if msg.get("type") == "Basic ID" and msg.get("id"):
                        serial_no = msg["id"]
                        break

                event: Dict[str, Any] = {
                    "timestamp": ts,
                    "timestamp_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                    "transport": transport,
                    "interface": self.interface,
                    "channel": cur_ch,
                    "band": cur_band,
                    "frequency_mhz": cur_freq,
                    "counter": counter,
                    "mac": mac_addr,
                    "rssi_dbm": rssi_dbm,
                    "serial_number": serial_no,
                    "messages": parsed_messages,
                    "messages_b64": messages_b64,
                    "raw_length": len(frame),
                }

                self.event_queue.put(event)

            except Exception as e:
                if self.running:
                    logger.debug(f"Error processing Wi-Fi frame: {e}")

        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
        logger.info("[*] Wi-Fi Sniffer stopped.")

    def stop(self):
        self.running = False


# ============================================================================
# Thread 3: BLE Sniffer Thread (nRF Sniffer over UART)
# ============================================================================

class BleNrfSnifferThread(threading.Thread):
    """
    Drives nrf_bt_sniffer_json.py as an autonomous background sniffer subprocess over UART.
    Reads structured JSON records from stdout, normalizes them, and feeds the event queue.
    """
    def __init__(
        self,
        event_queue: queue.Queue,
        nrf_port: Optional[str] = None,
        rx_pcap: Optional[str] = None,
        coded: bool = False,
        ble_mode: str = "all",
    ):
        super().__init__(name="BleNrfSnifferThread", daemon=True)
        self.event_queue = event_queue
        self.nrf_port = nrf_port
        self.rx_pcap = rx_pcap
        self.coded = coded
        self.ble_mode = ble_mode
        self.running = False
        self.proc: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        logger.info("[*] Starting BLE nRF Sniffer subprocess via nrf_bt_sniffer_json.py...")

        subprocess.run(["killall", "-9", "nrfutil", "nrfutil-ble-sniffer", "nrfutil-ble-sni"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.3)

        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate_paths = [
            os.path.join(script_dir, "nrf_bt_sniffer_json.py"),
            os.path.join(script_dir, "..", "evaluation", "nrf_bt_sniffer_json.py"),
            os.path.join(script_dir, "..", "nrf_bt_sniffer_json.py"),
        ]
        nrf_script = next((p for p in candidate_paths if os.path.exists(p)), candidate_paths[0])

        cmd = [sys.executable, nrf_script, "--only-rid"]
        if self.nrf_port:
            cmd.extend(["--nrf-port", self.nrf_port])
        elif self.rx_pcap and os.path.exists(self.rx_pcap):
            cmd.extend(["--rx-pcap", self.rx_pcap])

        if self.coded:
            cmd.append("--coded")
        if self.ble_mode in ("ble5", "extended", "pure_bt5", "bt5"):
            cmd.append("-b")

        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=sys.stderr, text=True, start_new_session=True)
            logger.info("[*] BLE nRF Sniffer process active.")

            while self.running and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if not line:
                    continue

                line_str = line.strip()
                if not line_str.startswith("{"):
                    continue

                try:
                    record = json.loads(line_str)
                    mac = record.get("mac")
                    ts = record.get("timestamp", time.time())
                    rid_info = record.get("remote_id")

                    if not mac or mac == "UNKNOWN" or not rid_info:
                        continue

                    parsed_msgs = rid_info.get("parsed_messages", [])
                    raw_hex = record.get("raw_hex", "")
                    transport_type = rid_info.get("transport", "ble4")
                    transport = "bt5" if transport_type in ("bt5", "ble5", "extended") else "bt4"

                    # Generate messages_b64 from parsed message hex blocks or raw
                    messages_b64 = []
                    for msg in parsed_msgs:
                        if isinstance(msg, dict) and "raw_hex" in msg:
                            raw_b = bytes.fromhex(msg["raw_hex"])
                            messages_b64.append(base64.b64encode(raw_b[:25]).decode('ascii'))

                    serial_no = None
                    for msg in parsed_msgs:
                        if isinstance(msg, dict) and msg.get("type") == "Basic ID" and msg.get("id"):
                            serial_no = msg["id"]
                            break

                    counter = rid_info.get("counter", 0)

                    event: Dict[str, Any] = {
                        "timestamp": ts,
                        "timestamp_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                        "transport": transport,
                        "interface": "nRF52840-UART",
                        "channel": "Adv (37/38/39)",
                        "band": "2.4GHz",
                        "frequency_mhz": 2402,
                        "counter": counter,
                        "mac": mac.upper(),
                        "rssi_dbm": record.get("rssi_dbm"),
                        "serial_number": serial_no,
                        "messages": parsed_msgs,
                        "messages_b64": messages_b64,
                        "raw_length": record.get("raw_length", 0),
                        "pdu_type": record.get("pdu_type"),
                    }

                    self.event_queue.put(event)

                except Exception as e:
                    logger.debug(f"Error parsing BLE JSON record: {e}")

        except Exception as e:
            if self.running:
                logger.error(f"[-] Failed to run nrf_bt_sniffer_json.py: {e}")
        finally:
            self.stop_process()
            self.running = False
            logger.info("[*] BLE nRF Sniffer stopped.")

    def stop_process(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                time.sleep(0.2)
                os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None

    def stop(self):
        self.running = False
        self.stop_process()


# ============================================================================
# Main / Real-Time Formatted Console & Storage Logger
# ============================================================================

class UnifiedTelemetryLogger:
    """
    Consumes parsed RID events and manages:
    1. Colorized live console display.
    2. Append-only replay-compatible JSONL log.
    3. SQLite 5-minute flight encounter grouping & persistence.
    """
    def __init__(
        self,
        log_jsonl_path: Optional[str] = None,
        db_path: Optional[str] = "rid_detections.db",
        encounter_timeout_s: float = 300.0
    ):
        self.log_file_handle = open(log_jsonl_path, "a") if log_jsonl_path else None
        self.encounter_tracker = EncounterTracker(db_path=db_path, timeout_s=encounter_timeout_s) if db_path else None
        self.stats = {
            "total_packets": 0,
            "transports": {"bt4": 0, "bt5": 0, "wifi": 0, "nan": 0},
            "macs": set(),
            "serials": set(),
            "channels": {},
        }
        self.mac_to_serial: Dict[str, str] = {}
        self.start_time = time.time()
        self.first_packet_time: Optional[float] = None
        self.last_timeout_check = time.time()

    def process_event(self, event: Dict[str, Any]):
        now = time.time()
        if self.first_packet_time is None:
            self.first_packet_time = event.get("timestamp", now)

        # Calculate time_offset_ms relative to first packet for replay_drones.py
        time_offset_ms = int((event.get("timestamp", now) - self.first_packet_time) * 1000)

        self.stats["total_packets"] += 1
        t_key = event.get("transport", "unknown")
        self.stats["transports"][t_key] = self.stats["transports"].get(t_key, 0) + 1

        mac = event.get("mac", "UNKNOWN")
        self.stats["macs"].add(mac)

        serial = event.get("serial_number")
        if serial:
            self.stats["serials"].add(serial)
            self.mac_to_serial[mac] = serial
        elif mac in self.mac_to_serial:
            serial = self.mac_to_serial[mac]
            event["serial_number"] = serial

        ch_str = str(event.get("channel", "N/A"))
        self.stats["channels"][ch_str] = self.stats["channels"].get(ch_str, 0) + 1

        # 1. Update SQLite 5-minute Encounter Tracker
        encounter_id = None
        if self.encounter_tracker:
            encounter_id = self.encounter_tracker.update_with_packet(event)

            # Periodic sweep for timed out encounters every 15 seconds
            if now - self.last_timeout_check > 15.0:
                closed = self.encounter_tracker.check_timeouts(now)
                for c_id in closed:
                    print(f"{C_GRAY}[*] Flight Encounter {c_id} closed (5-minute silence timeout).{C_RESET}")
                self.last_timeout_check = now

        # 2. Write to Replay-Compatible JSONL
        if self.log_file_handle:
            replay_record = {
                "time_offset_ms": time_offset_ms,
                "transport": t_key,
                "counter": event.get("counter", 0),
                "messages_b64": event.get("messages_b64", []),
                "mac": mac,
                "serial": serial,
                "channel": event.get("channel"),
                "rssi_dbm": event.get("rssi_dbm"),
                "timestamp_iso": event.get("timestamp_iso"),
                "encounter_id": encounter_id,
            }
            self.log_file_handle.write(json.dumps(replay_record) + "\n")
            self.log_file_handle.flush()

        # 3. Format Live Console Banner
        transport_badges = {
            "bt4": f"{C_BLUE}[BLE 4 LEGACY]{C_RESET}",
            "bt5": f"{C_CYAN}[BLE 5 EXT]{C_RESET}",
            "wifi": f"{C_GREEN}[WIFI BEACON]{C_RESET}",
            "nan": f"{C_YELLOW}[WIFI NAN]{C_RESET}",
        }
        badge = transport_badges.get(t_key, f"{C_WHITE}[{t_key.upper()}]{C_RESET}")

        rssi_val = event.get("rssi_dbm")
        rssi_str = f"{rssi_val:+d} dBm" if rssi_val is not None else "Unknown RSSI"

        band_str = event.get("band", "")
        ch_display = f"Ch {ch_str}" if ch_str != "N/A" else ""
        rf_info = f"{band_str} {ch_display}".strip()

        dt_str = datetime.fromtimestamp(event.get("timestamp", now)).strftime("%H:%M:%S.%f")[:-3]
        enc_tag = f" {C_GRAY}({encounter_id}){C_RESET}" if encounter_id else ""

        print(f"\n{C_BOLD}🚁 DRONE RID DETECTED {badge}{enc_tag} {C_GRAY}{dt_str}{C_RESET}")
        print(f"   {C_WHITE}MAC: {C_BOLD}{mac}{C_RESET} | {C_WHITE}RSSI: {C_BOLD}{rssi_str}{C_RESET} | {C_WHITE}RF: {C_MAGENTA}{rf_info}{C_RESET}")
        if serial:
            print(f"   {C_GREEN}Serial / UAS ID: {C_BOLD}{serial}{C_RESET}")

        # Print decoded telemetry blocks
        for msg in event.get("messages", []):
            m_type = msg.get("type", "Unknown")
            proto_name = msg.get("proto_version_name", "")
            ver_tag = f" {C_GRAY}[{proto_name}]{C_RESET}" if proto_name else ""

            if m_type == "Location":
                lat = msg.get("lat")
                lon = msg.get("lon")
                alt = msg.get("geodetic_altitude_m") or msg.get("pressure_altitude_m")
                height = msg.get("height_m")
                h_type_name = msg.get("height_type_name", "")
                spd = msg.get("speed_mps")
                heading = msg.get("direction_deg")
                status_name = msg.get("status_name", "")

                loc_parts = []
                if status_name:
                    loc_parts.append(f"Status: {status_name}")
                if lat is not None and lon is not None:
                    loc_parts.append(f"Pos: ({lat:.6f}, {lon:.6f})")
                if alt is not None:
                    loc_parts.append(f"Alt: {alt:.1f}m")
                if height is not None:
                    loc_parts.append(f"H: {height:.1f}m ({h_type_name})")
                if spd is not None:
                    loc_parts.append(f"Speed: {spd:.1f}m/s")
                if heading is not None:
                    loc_parts.append(f"Hdg: {heading}°")

                acc_parts = []
                if msg.get("horizontal_accuracy_name") and msg.get("horizontal_accuracy", 0) > 0:
                    acc_parts.append(f"HAcc: {msg['horizontal_accuracy_name']}")
                if msg.get("vertical_accuracy_name") and msg.get("vertical_accuracy", 0) > 0:
                    acc_parts.append(f"VAcc: {msg['vertical_accuracy_name']}")
                if msg.get("speed_accuracy_name") and msg.get("speed_accuracy", 0) > 0:
                    acc_parts.append(f"SpdAcc: {msg['speed_accuracy_name']}")

                print(f"   {C_CYAN}📍 Location  {C_RESET}{ver_tag} -> {' | '.join(loc_parts)}")
                if acc_parts:
                    print(f"      {C_GRAY}Accuracies: {', '.join(acc_parts)}{C_RESET}")

            elif m_type == "Basic ID":
                b_id = msg.get("id")
                id_type_name = msg.get("id_type_name", f"Type {msg.get('id_type')}")
                ua_type_name = msg.get("ua_type_name", f"UA {msg.get('ua_type')}")
                print(f"   {C_YELLOW}🆔 Basic ID  {C_RESET}{ver_tag} -> ID: {b_id} | Type: {id_type_name} | Aircraft: {ua_type_name}")

            elif m_type == "System":
                p_lat = msg.get("pilot_lat")
                p_lon = msg.get("pilot_lon")
                p_alt = msg.get("pilot_alt_m")
                radius = msg.get("area_radius_m")
                op_loc_type = msg.get("operator_location_type_name", "")
                class_type = msg.get("classification_type_name", "")

                sys_parts = []
                if p_lat is not None and p_lon is not None:
                    sys_parts.append(f"Pilot: ({p_lat:.6f}, {p_lon:.6f}) [{op_loc_type}]")
                if p_alt is not None:
                    sys_parts.append(f"Alt: {p_alt:.1f}m")
                if radius:
                    sys_parts.append(f"Radius: {radius}m")
                if msg.get("classification_type") == 1:  # EU
                    sys_parts.append(f"EU Category: {msg.get('category_eu_name')} / {msg.get('class_eu_name')}")
                if msg.get("system_timestamp_iso"):
                    sys_parts.append(f"TS: {msg['system_timestamp_iso']}")

                print(f"   {C_MAGENTA}🎮 System    {C_RESET}{ver_tag} -> {' | '.join(sys_parts)}")

            elif m_type == "Operator ID":
                op_id = msg.get("operator_id")
                op_id_type = msg.get("operator_id_type_name", "Operator ID")
                print(f"   {C_WHITE}👤 Operator  {C_RESET}{ver_tag} -> {op_id_type}: {op_id}")

            elif m_type == "Self-ID":
                desc = msg.get("description")
                desc_type = msg.get("desc_type_name", "Text")
                print(f"   {C_WHITE}📝 Self-ID   {C_RESET}{ver_tag} -> [{desc_type}] \"{desc}\"")

            elif m_type == "Auth":
                auth_type_name = msg.get("auth_type_name", "Auth")
                page_num = msg.get("page_number", 0)
                auth_hex = msg.get("auth_data_hex", "")
                if page_num == 0:
                    auth_len = msg.get("auth_data_length", len(auth_hex)//2)
                    print(f"   {C_BLUE}🔒 Auth      {C_RESET}{ver_tag} -> Type: {auth_type_name} | Page: 0/{msg.get('last_page_index', 0)} (Len: {auth_len}B) | Hex: {auth_hex[:32]}...")
                else:
                    print(f"   {C_BLUE}🔒 Auth      {C_RESET}{ver_tag} -> Type: {auth_type_name} | Page: {page_num} | Hex: {auth_hex[:32]}...")

        sys.stdout.flush()

    def close(self):
        if self.encounter_tracker:
            self.encounter_tracker.finalize_all()
        if self.log_file_handle:
            self.log_file_handle.close()

    def print_summary(self):
        duration = time.time() - self.start_time
        print(f"\n{C_BOLD}{'='*60}{C_RESET}")
        print(f"{C_BOLD}📊 CAPTURE SUMMARY ({duration:.1f}s elapsed){C_RESET}")
        print(f"{C_BOLD}{'='*60}{C_RESET}")
        print(f"  • Total RID Packets Captured : {C_BOLD}{self.stats['total_packets']}{C_RESET}")
        print(f"  • Unique Drones (MACs)       : {C_BOLD}{len(self.stats['macs'])}{C_RESET}")
        print(f"  • Unique UAS Serial Numbers  : {C_BOLD}{len(self.stats['serials'])}{C_RESET}")
        print(f"  • Physical Transport Breakdown:")
        for t_name, count in self.stats["transports"].items():
            print(f"      - {t_name:<12}: {count}")
        print(f"  • Wi-Fi / BLE Channels Active:")
        for ch, count in sorted(self.stats["channels"].items()):
            print(f"      - Channel {ch:<8}: {count} packets")
        print(f"{C_BOLD}{'='*60}{C_RESET}\n")


# ============================================================================
# Monitor Mode Setup Helpers
# ============================================================================

def setup_monitor_mode(interface: str, initial_channel: int = 6):
    """Put interface into monitor mode and bring it up."""
    logger.info(f"[*] Configuring {interface} into monitor mode...")
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True)
        subprocess.run(["iw", "dev", interface, "set", "type", "monitor"], check=True)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True)
        subprocess.run(["iw", "dev", interface, "set", "channel", str(initial_channel)], check=True)
        logger.info(f"[*] {interface} is ready in monitor mode on Channel {initial_channel}.")
    except Exception as e:
        logger.warning(f"[!] Warning: Could not configure monitor mode on {interface}: {e}")


def restore_managed_mode(interface: str):
    """Restore interface to managed mode."""
    logger.info(f"[*] Restoring {interface} to managed mode...")
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True, stderr=subprocess.DEVNULL)
    except Exception as e:
        logger.debug(f"Failed to restore {interface}: {e}")


# ============================================================================
# Main Entrypoint & CLI Parsing
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Combined Bluetooth (nRF UART) and Wi-Fi Drone Remote ID Listener and Console Logger",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Hardware & Interfaces
    parser.add_argument("--wifi-iface", "-i", default=None, help="Wi-Fi monitor-mode interface (e.g., wlan1)")
    parser.add_argument("--nrf-port", "-p", default=None, help="nRF Sniffer UART serial port (e.g., /dev/ttyACM0). Auto-detected if omitted.")
    parser.add_argument("--rx-pcap", help="Replay pre-captured BLE pcap file for offline verification")

    # Subsystem toggles
    parser.add_argument("--no-wifi", action="store_true", help="Disable Wi-Fi sniffing and channel hopping")
    parser.add_argument("--no-ble", action="store_true", help="Disable Bluetooth sniffing")
    parser.add_argument("--no-wifi-setup", action="store_true", help="Skip bringing Wi-Fi interface down/up into monitor mode")

    # Hopping Schedule Configuration
    parser.add_argument("--non-social-ratio", "-k", type=int, default=1,
                        help="Non-social channel ratio multiplier k (cycles 2k non-social on 2.4GHz for every k on 5.8GHz)")
    parser.add_argument("--social-dwell-ms", type=int, default=1000, help="Social channel dwell time in milliseconds (1 Hz)")
    parser.add_argument("--non-social-dwell-ms", type=int, default=200, help="Non-social channel dwell time in milliseconds (5 Hz)")
    parser.add_argument("--intraband-delay-ms", type=int, default=30, help="Intraband channel switching delay in ms (empirical estimate, configurable for Wi-Fi chipset/driver)")
    parser.add_argument("--interband-delay-ms", type=int, default=50, help="Interband channel switching delay in ms (empirical estimate, configurable for Wi-Fi chipset/driver)")

    # BLE Options
    parser.add_argument("--coded", action="store_true", help="Enable Bluetooth 5 Long Range (LE Coded PHY) scanning")
    parser.add_argument("--ble-mode", choices=["all", "legacy", "extended"], default="all", help="BLE advertisement filter mode")

    # Storage & Logging
    parser.add_argument("--db-file", default="rid_detections.db", help="SQLite database path for 5-minute flight encounter records (set empty '' to disable)")
    parser.add_argument("--encounter-timeout-s", type=float, default=300.0, help="Flight encounter timeout in seconds (default 300s / 5 minutes)")
    parser.add_argument("--log-jsonl", default=None, help="Optional replay-compatible JSONL log file path")

    args = parser.parse_args()

    if args.no_wifi and args.no_ble:
        logger.error("[-] Both Wi-Fi and BLE are disabled. Nothing to do!")
        sys.exit(1)

    if not args.no_wifi and not args.wifi_iface:
        logger.warning("[!] No --wifi-iface specified. Wi-Fi capture will be disabled unless --wifi-iface is provided.")
        args.no_wifi = True

    if os.geteuid() != 0 and not args.no_wifi:
        logger.warning("[!] Warning: Root privileges (sudo) are recommended for Wi-Fi monitor mode and raw socket capture.")

    event_queue: queue.Queue = queue.Queue()
    channel_state = SharedChannelState(initial_channel=SOCIAL_CHANNEL_2G)
    logger_worker = UnifiedTelemetryLogger(
        log_jsonl_path=args.log_jsonl,
        db_path=args.db_file if args.db_file else None,
        encounter_timeout_s=args.encounter_timeout_s
    )

    threads: List[threading.Thread] = []
    hopper_thread: Optional[WifiChannelHopperThread] = None
    wifi_thread: Optional[WifiSnifferThread] = None
    ble_thread: Optional[BleNrfSnifferThread] = None

    # Setup Wi-Fi
    if not args.no_wifi:
        if not args.no_wifi_setup:
            setup_monitor_mode(args.wifi_iface, initial_channel=SOCIAL_CHANNEL_2G)

        hopper_thread = WifiChannelHopperThread(
            interface=args.wifi_iface,
            channel_state=channel_state,
            non_social_ratio_k=args.non_social_ratio,
            social_dwell_ms=args.social_dwell_ms,
            non_social_dwell_ms=args.non_social_dwell_ms,
            intraband_delay_ms=args.intraband_delay_ms,
            interband_delay_ms=args.interband_delay_ms,
        )
        wifi_thread = WifiSnifferThread(
            interface=args.wifi_iface,
            channel_state=channel_state,
            event_queue=event_queue,
        )
        threads.extend([hopper_thread, wifi_thread])

    # Setup BLE
    if not args.no_ble:
        ble_thread = BleNrfSnifferThread(
            event_queue=event_queue,
            nrf_port=args.nrf_port,
            rx_pcap=args.rx_pcap,
            coded=args.coded,
            ble_mode=args.ble_mode,
        )
        threads.append(ble_thread)

    # Signal Handling for graceful shutdown
    stop_event = threading.Event()

    def shutdown(signum, frame):
        if not stop_event.is_set():
            stop_event.set()
            print(f"\n{C_YELLOW}[*] Shutting down combined listener...{C_RESET}")

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    print(f"\n{C_BOLD}{C_GREEN}🚀 COMBINED BLUETOOTH & WI-FI REMOTE ID LISTENER ACTIVE{C_RESET}")
    if args.db_file:
        print(f"  • SQLite Encounters DB: {C_MAGENTA}{args.db_file}{C_RESET} (Timeout: {args.encounter_timeout_s:.0f}s / {args.encounter_timeout_s/60:.1f}m)")
    if args.log_jsonl:
        print(f"  • Replay JSONL Log   : {C_MAGENTA}{args.log_jsonl}{C_RESET}")
    print(f"{C_GRAY}Press Ctrl+C at any time to stop and view capture statistics.{C_RESET}\n")

    # Start capture threads
    for t in threads:
        t.start()

    # Main logging loop
    try:
        while not stop_event.is_set():
            try:
                event = event_queue.get(timeout=0.1)
                logger_worker.process_event(event)
            except queue.Empty:
                continue
    except KeyboardInterrupt:
        shutdown(None, None)
    finally:
        # Stop all worker threads
        if hopper_thread:
            hopper_thread.stop()
        if wifi_thread:
            wifi_thread.stop()
        if ble_thread:
            ble_thread.stop()

        for t in threads:
            t.join(timeout=1.0)

        # Restore Wi-Fi interface if we configured it
        if not args.no_wifi and not args.no_wifi_setup and args.wifi_iface:
            restore_managed_mode(args.wifi_iface)

        # Drain any remaining events in queue
        while not event_queue.empty():
            try:
                logger_worker.process_event(event_queue.get_nowait())
            except Exception:
                break

        # Finalize encounters & close database/logs
        logger_worker.close()
        logger_worker.print_summary()


if __name__ == "__main__":
    main()
