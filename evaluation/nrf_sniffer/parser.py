#!/usr/bin/env python3
"""
Universal ASTM F3411-19 / ASTM F3411-22 / OpenDroneID Spec Parser
Decodes all ASTM Remote ID message types:
  - Type 0: Basic ID (UAS Serial, ID Type, UA Aircraft Type)
  - Type 1: Location & Vector (Coordinates, Altitudes, Speed, Heading, Accuracies)
  - Type 2: Authentication (Pages, Signature/Data, Timestamps)
  - Type 3: Self-ID (Operator/Operation Text Description)
  - Type 4: System (Pilot Coordinates, Operator Location, Area/Radius, EU Classification)
  - Type 5: Operator ID (CAA Operator Registration)
  - Type 0xF: Message Pack (Multi-message containers)

Standard library only (struct, datetime, re) with zero external dependencies.
"""

import base64
import logging
import struct
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .error_log import log_failure

logger = logging.getLogger("CombinedRIDListener.Parser")

ASTM_OUI = b"\xfa\x0b\xbc"      # OpenDroneID / ASTM OUI in Wi-Fi Vendor IE
APP_CODE_RID = 0x0D             # Application Code for Drone Remote ID
BLE_RID_UUID = b"\xfa\xff"      # 16-bit UUID 0xFFFA (Little-Endian)
# Wi-Fi NAN Service Discovery Frame: Public Action (category 0x04), Vendor Specific (action 0x09),
# Wi-Fi Alliance OUI 50:6F:9A with OUI type 0x13 (NAN), followed by NAN attributes
NAN_SDF_HEADER = b"\x04\x09\x50\x6f\x9a\x13"
NAN_ATTR_SERVICE_DESCRIPTOR = 0x03
# NAN Service ID of Remote ID: first 6 bytes of SHA-256("org.opendroneid.remoteid")
NAN_RID_SERVICE_ID = b"\x88\x69\x19\x9d\x92\x09"
OPENDRONEID_EPOCH_2019 = 1546300800  # 2019-01-01 00:00:00 UTC Unix Epoch

# Anomaly codes attached to decoded messages under "anomalies" when a transmitter
# uses an off-spec encoding that is still decoded; aggregated per encounter downstream.
ANOMALY_DIRECTION_EW_CLEAR_OVER_179 = "direction_ew_clear_over_179"
ANOMALY_DIRECTION_OVER_360 = "direction_over_360"

# Packet-level anomaly codes attached by the capture backends under the event's "anomalies"
# when a frame failed its link-layer integrity check but was still decoded.
ANOMALY_WIFI_FCS_BAD = "wifi_fcs_bad"
ANOMALY_BLE_CRC_BAD = "ble_crc_bad"
# Set when rebuilding from logs: a BLE packet logged before PHY/CRC were recorded whose raw frame
# could not be found, so its MAC, PHY and CRC status are unverified (PHY left empty)
ANOMALY_BLE_RAW_FRAME_UNAVAILABLE = "ble_raw_frame_unavailable"
# Set by the encounter tracker: a CRC/FCS-failed packet whose MAC has no encounter, attributed to
# the one encounter whose received Basic ID / Operator ID messages (and MAC) it nearly matches
ANOMALY_MATCHED_BY_SIMILARITY = "matched_by_similarity"

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
    4: "Specific Session ID",
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
    4: "Remote ID System Failure",
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
    1: "< 0.1 s",
    2: "< 0.2 s",
    3: "< 0.3 s",
    4: "< 0.4 s",
    5: "< 0.5 s",
    6: "< 0.6 s",
    7: "< 0.7 s",
    8: "< 0.8 s",
    9: "< 0.9 s",
    10: "< 1.0 s",
    11: "< 1.1 s",
    12: "< 1.2 s",
    13: "< 1.3 s",
    14: "< 1.4 s",
    15: "< 1.5 s",
}

AUTH_TYPE_NAMES = {
    0x0: "None / Reserved",
    0x1: "UAS ID Signature",
    0x2: "Operator ID Signature",
    0x3: "Message Set Signature",
    0x4: "Network Remote ID Auth",
    0x5: "Specific Auth Method (SAM)",
}

DESC_TYPE_NAMES = {
    0x0: "Text",
    0x1: "Emergency Status",
    0x2: "Extended Status",
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


# Protocol version that introduced a field or enum value, per the standards behind each version
# (checked against opendroneid-core-c, libopendroneid/opendroneid.h). In an older message the field
# is reserved and not reported (None), and the value is labelled "Reserved":
#   v1 (ASD-STAN prEN 4709-002 P1 / ASTM F3411 v1.1 draft): Basic ID type 4 (Specific Session ID),
#      Auth type 5 (Specific Authentication Method), System classification type, EU category and
#      class, operator geodetic altitude
#   v2 (ASTM F3411-22): Location status 4 (Remote ID System Failure), Self-ID description types
#      1 (Emergency) and 2 (Extended Status), System timestamp
ID_TYPE_SINCE_VERSION = {4: 1}
AUTH_TYPE_SINCE_VERSION = {5: 1}
STATUS_SINCE_VERSION = {4: 2}
DESC_TYPE_SINCE_VERSION = {1: 2, 2: 2}
SYSTEM_CLASSIFICATION_SINCE_VERSION = 1
SYSTEM_OPERATOR_ALTITUDE_SINCE_VERSION = 1
SYSTEM_TIMESTAMP_SINCE_VERSION = 2


def _enum_name(names: Dict[int, str], value: int, since_version: Dict[int, int], proto_ver: int) -> str:
    """The name of an enum value, "Reserved (n)" if unknown or introduced after proto_ver."""
    if since_version.get(value, 0) > proto_ver:
        return f"Reserved ({value})"
    return names.get(value, f"Reserved ({value})")


def sanitize_ascii_string(data: bytes, max_len: int = 25) -> str:
    """Sanitize ASCII string removing non-printable and control bytes."""
    cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', data[:max_len].decode('ascii', errors='ignore')).strip()
    return cleaned


def _decode_lat_lon(lat_raw: int, lon_raw: int) -> Tuple[Optional[float], Optional[float]]:
    """Decode 1e-7 degree coordinates; (0, 0) means unknown and out-of-range values are rejected."""
    if lat_raw == 0 and lon_raw == 0:
        return None, None
    lat = lat_raw / 1e7
    lon = lon_raw / 1e7
    if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0):
        return None, None
    return lat, lon


def decode_astm_message(block: bytes) -> Optional[Dict[str, Any]]:
    """Decode a single 25-byte ASTM F3411 message block."""
    if len(block) < 25:
        return None

    header = block[0]
    msg_type = (header >> 4) & 0x0F
    proto_ver = header & 0x0F

    # Reject unsupported or garbage message types
    if msg_type not in (0x0, 0x1, 0x2, 0x3, 0x4, 0x5):
        return None

    is_zeroed = (len(block) >= 25 and block[1:25] == b'\x00' * 24)
    is_known_version = proto_ver in PROTO_VERSION_NAMES

    result: Dict[str, Any] = {
        "msg_type": msg_type,
        "type": MSG_TYPE_NAMES.get(msg_type, f"Unknown ({msg_type})"),
        "protocol_version": proto_ver,
        "proto_version_name": PROTO_VERSION_NAMES.get(proto_ver, f"Unknown Version (v{proto_ver})"),
        "is_known_version": is_known_version,
        "raw_hex": block[:25].hex().upper(),
        "is_zeroed": is_zeroed,
    }

    if not is_known_version:
        result["raw_payload_hex"] = block[1:25].hex().upper()
        result["unparsed_reason"] = f"Unknown protocol version {proto_ver}; payload layout unsupported"
        return result

    try:
        if msg_type == 0x0:  # Basic ID (Type 0)
            id_type_raw = block[1]
            id_type = (id_type_raw >> 4) & 0x0F
            ua_type = id_type_raw & 0x0F
            uas_id = sanitize_ascii_string(block[2:22], max_len=20)
            result.update({
                "id": uas_id,
                "id_type": id_type,
                "id_type_name": _enum_name(ID_TYPE_NAMES, id_type, ID_TYPE_SINCE_VERSION, proto_ver),
                "ua_type": ua_type,
                "ua_type_name": UA_TYPE_NAMES.get(ua_type, f"Reserved ({ua_type})"),
            })

        elif msg_type == 0x1:  # Location / Vector (Type 1)
            b1 = block[1]
            status = (b1 >> 4) & 0x0F
            height_type = (b1 >> 2) & 0x01
            ew_dir = (b1 >> 1) & 0x01
            speed_mult = b1 & 0x01

            # Direction: 0-179 encoded directly (E/W bit clear), 180-360 as value-180 with E/W bit set.
            # 361 (raw 181, E/W set) is the spec's "unknown" value. Off-spec encodings are decoded
            # anyway (> 360 normalized into 0-359) and flagged in the message's "anomalies" list.
            anomalies: List[str] = []
            dir_raw = block[2]
            direction_deg = dir_raw + 180 if ew_dir else dir_raw
            if direction_deg == 361:
                direction_deg = None
            else:
                if not ew_dir and dir_raw > 179:
                    anomalies.append(ANOMALY_DIRECTION_EW_CLEAR_OVER_179)
                if direction_deg > 360:
                    anomalies.append(ANOMALY_DIRECTION_OVER_360)
                    direction_deg %= 360
            if anomalies:
                logger.warning(
                    f"Off-spec Location direction ({', '.join(anomalies)}): raw {dir_raw}, "
                    f"E/W bit {ew_dir}; decoded as {direction_deg} deg. Block: {block[:25].hex().upper()}"
                )

            # Horizontal speed: unknown (255 m/s) encodes as raw 255 with the multiplier bit set.
            # Raw 255 without the multiplier is a valid 63.75 m/s.
            speed_raw = block[3]
            if speed_raw == 255 and speed_mult == 1:
                speed_mps = None
            else:
                speed_mps = (speed_raw * 0.25) if speed_mult == 0 else (63.75 + speed_raw * 0.75)

            # Vertical speed: 0.5 m/s steps, valid range +/-62 m/s (raw +/-124).
            # Unknown (63 m/s) encodes as raw 126; anything beyond +/-124 is out of spec.
            v_speed_raw = struct.unpack('<b', block[4:5])[0]
            v_speed_mps = None if abs(v_speed_raw) > 124 else (v_speed_raw * 0.5)

            lat_raw = struct.unpack('<i', block[5:9])[0]
            lon_raw = struct.unpack('<i', block[9:13])[0]
            lat, lon = _decode_lat_lon(lat_raw, lon_raw)

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

            chosen_alt = g_alt_m if g_alt_m is not None else p_alt_m

            result.update({
                "status": status,
                "status_name": _enum_name(STATUS_NAMES, status, STATUS_SINCE_VERSION, proto_ver),
                "direction_deg": direction_deg,
                "heading": direction_deg,
                "speed_mps": round(speed_mps, 2) if speed_mps is not None else None,
                "speed": round(speed_mps, 2) if speed_mps is not None else None,
                "vertical_speed_mps": round(v_speed_mps, 2) if v_speed_mps is not None else None,
                "lat": lat,
                "lon": lon,
                "pressure_altitude_m": round(p_alt_m, 2) if p_alt_m is not None else None,
                "geodetic_altitude_m": round(g_alt_m, 2) if g_alt_m is not None else None,
                "alt": round(chosen_alt, 2) if chosen_alt is not None else None,
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
            if anomalies:
                result["anomalies"] = anomalies

        elif msg_type == 0x2:  # Auth (Type 2)
            # Decoded alike for all versions, as F3411-22 defines it (and opendroneid decodes it):
            # page 0 carries the last page index, and pages run up to 15. F3411-19 (v0) allows only
            # pages 0-4 (the higher values reserved), and ASD-STAN prEN 4709-002 has no Auth message.
            b1 = block[1]
            auth_type = (b1 >> 4) & 0x0F
            page_num = b1 & 0x0F

            result.update({
                "auth_type": auth_type,
                "auth_type_name": _enum_name(AUTH_TYPE_NAMES, auth_type, AUTH_TYPE_SINCE_VERSION, proto_ver),
                "page_number": page_num,
                "page": page_num,
            })

            if page_num == 0:
                last_page_idx = block[2]
                length = block[3]
                ts_raw = struct.unpack('<I', block[4:8])[0]
                auth_ts_epoch = (OPENDRONEID_EPOCH_2019 + ts_raw) if ts_raw > 0 else None
                auth_data_hex = block[8:25].hex().upper()
                result.update({
                    "last_page_index": last_page_idx,
                    "auth_data_length": length,
                    "auth_timestamp_epoch": auth_ts_epoch,
                    "auth_data_hex": auth_data_hex,
                    "data": auth_data_hex,
                })
            else:
                auth_data_hex = block[2:25].hex().upper()
                result.update({
                    "auth_data_hex": auth_data_hex,
                    "data": auth_data_hex,
                })

        elif msg_type == 0x3:  # Self-ID (Type 3)
            desc_type = block[1]
            desc = sanitize_ascii_string(block[2:25], max_len=23)
            result.update({
                "desc_type": desc_type,
                "desc_type_name": _enum_name(DESC_TYPE_NAMES, desc_type, DESC_TYPE_SINCE_VERSION, proto_ver),
                "description": desc,
                "desc": desc,
            })

        elif msg_type == 0x4:  # System (Type 4)
            b1 = block[1]
            op_loc_type = b1 & 0x03
            class_type = (b1 >> 2) & 0x07

            op_lat_raw = struct.unpack('<i', block[2:6])[0]
            op_lon_raw = struct.unpack('<i', block[6:10])[0]
            pilot_lat, pilot_lon = _decode_lat_lon(op_lat_raw, op_lon_raw)

            area_count = struct.unpack('<H', block[10:12])[0]
            area_radius = block[12] * 10

            area_ceil_raw = struct.unpack('<H', block[13:15])[0]
            area_ceil_m = (area_ceil_raw * 0.5 - 1000.0) if area_ceil_raw != 0 else None

            area_floor_raw = struct.unpack('<H', block[15:17])[0]
            area_floor_m = (area_floor_raw * 0.5 - 1000.0) if area_floor_raw != 0 else None

            # Fields a later protocol version added are reserved in older messages: not reported
            category_eu = class_eu = pilot_alt_m = sys_ts_epoch = None
            if proto_ver < SYSTEM_CLASSIFICATION_SINCE_VERSION:
                class_type = None
            else:
                b17 = block[17]
                category_eu = (b17 >> 4) & 0x0F
                class_eu = b17 & 0x0F

            if proto_ver >= SYSTEM_OPERATOR_ALTITUDE_SINCE_VERSION:
                op_alt_raw = struct.unpack('<H', block[18:20])[0]
                pilot_alt_m = (op_alt_raw * 0.5 - 1000.0) if op_alt_raw != 0 else None

            if proto_ver >= SYSTEM_TIMESTAMP_SINCE_VERSION:
                sys_ts_raw = struct.unpack('<I', block[20:24])[0]
                sys_ts_epoch = (OPENDRONEID_EPOCH_2019 + sys_ts_raw) if sys_ts_raw > 0 else None
            sys_ts_iso = datetime.fromtimestamp(sys_ts_epoch, timezone.utc).isoformat() if sys_ts_epoch else None

            def name(names, value):
                return None if value is None else names.get(value, f"Reserved ({value})")

            result.update({
                "operator_location_type": op_loc_type,
                "operator_location_type_name": OPERATOR_LOCATION_TYPE_NAMES.get(op_loc_type, "Reserved"),
                "classification_type": class_type,
                "classification_type_name": name(CLASSIFICATION_TYPE_NAMES, class_type),
                "pilot_lat": pilot_lat,
                "pilot_lon": pilot_lon,
                "area_count": area_count,
                "area_radius_m": area_radius,
                "area_ceiling_m": area_ceil_m,
                "area_floor_m": area_floor_m,
                "category_eu": category_eu,
                "category_eu_name": name(EU_CATEGORY_NAMES, category_eu),
                "class_eu": class_eu,
                "class_eu_name": name(EU_CLASS_NAMES, class_eu),
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
                "id": op_id,
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
            # A Message Pack encapsulates the complete broadcast message set; do not parse trailing frame padding
            break

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


def decode_message_blocks(messages_b64: Optional[List[str]]) -> List[Dict[str, Any]]:
    """
    Decoded messages of logged or streamed message blocks (base64, 25 bytes each; a pack is
    unpacked). A block that is not valid base64 is skipped and reported, one that is no known
    message is skipped as before.
    """
    messages: List[Dict[str, Any]] = []
    for block in messages_b64 or []:
        try:
            raw = base64.b64decode(block)
        except (ValueError, TypeError) as e:
            log_failure(logger, "message-block-base64", "[-] Skipped a message block that is not valid base64", e)
            continue
        parsed, _ = parse_astm_payload(raw)
        if parsed:
            messages.extend(parsed)
        else:
            decoded = decode_astm_message(raw)
            if decoded:
                messages.append(decoded)
    return messages


# AD structure lengths of ASTM Remote ID service data: one message, or a pack of 1-9 messages
ASTM_SERVICE_DATA_LENGTHS = frozenset([5 + 25] + [8 + 25 * n for n in range(1, 10)])


def astm_service_data_length(adv_data: bytes, offset: int) -> Optional[int]:
    """
    The AD structure length ASTM F3411 prescribes for the Remote ID service data starting at
    offset (length byte, AD type 0x16, UUID 0xFFFA, application code, counter, messages): 30 for
    one 25-byte message, 8 + 25 * N for a message pack of N messages (pack header: message type,
    message size, count). None if the pack's count is not 1-9 or not in the data.
    """
    first = offset + 6  # first message byte, after length, type, UUID, app code and counter
    if first >= len(adv_data):
        return None
    if adv_data[first] >> 4 != 0xF:
        return 5 + 25
    if first + 2 >= len(adv_data) or not 1 <= adv_data[first + 2] <= 9:
        return None
    return 8 + 25 * adv_data[first + 2]


def nan_service_info_length(service_info: bytes) -> Optional[int]:
    """
    The Service Info length ASTM F3411 prescribes for the Remote ID service info given (counter,
    then messages): 1 + 25 for one message, 1 + 3 + 25 * N for a message pack of N messages.
    None if the pack's count is not 1-9 or not in the data.
    """
    if len(service_info) < 2:
        return None
    if service_info[1] >> 4 != 0xF:
        return 1 + 25
    if len(service_info) < 4 or not 1 <= service_info[3] <= 9:
        return None
    return 1 + 3 + 25 * service_info[3]


def extract_nan_rid_payload(mpdu: bytes, repair_lengths: bool = False) -> Optional[Tuple[int, bytes]]:
    """
    ASTM F3411 Remote ID extractor for Wi-Fi NAN Service Discovery Frames.

    mpdu is the 802.11 frame without radiotap header. Walks the frame structure:
      - Action / Action No Ack management frame (+4 byte HT Control if the Order bit is set)
      - Public Action category 0x04, Vendor Specific action 0x09, OUI 50:6F:9A, OUI type 0x13
      - NAN attributes (ID 1 byte, length 2 bytes little-endian, body) up to the Service
        Descriptor Attribute (0x03) with the Remote ID Service ID (NAN_RID_SERVICE_ID)
      - in it, after Instance ID, Requestor Instance ID and Service Control, the optional Binding
        Bitmap, Matching Filter and Service Response Filter that Service Control announces
      - the Service Info: message counter (1 byte), then the message pack
    Bytes after the attributes (e.g. an appended FCS) are ignored.

    repair_lengths is for frames that failed their FCS: a Remote ID attribute whose attribute or
    Service Info length runs past the data, or a Service Info length that is no length ASTM
    allows, is read with the length its content prescribes (nan_service_info_length), cut to
    the data present.

    Returns:
        (counter, astm_bytes) or None if not a NAN Remote ID frame.
    """
    if len(mpdu) < 24 or mpdu[0] not in (0xD0, 0xE0) or mpdu[1] & 0x40:
        return None
    offset = 24 + (4 if mpdu[1] & 0x80 else 0)
    if mpdu[offset:offset + len(NAN_SDF_HEADER)] != NAN_SDF_HEADER:
        return None
    offset += len(NAN_SDF_HEADER)
    total_len = len(mpdu)

    while offset + 3 <= total_len:
        attr_id = mpdu[offset]
        attr_len = mpdu[offset + 1] | (mpdu[offset + 2] << 8)
        body_start = offset + 3
        is_rid = (attr_id == NAN_ATTR_SERVICE_DESCRIPTOR
                  and mpdu[body_start:body_start + 6] == NAN_RID_SERVICE_ID)
        if body_start + attr_len > total_len:
            if not (repair_lengths and is_rid):
                return None
            attr_len = total_len - body_start
        offset = body_start + attr_len
        if not is_rid:
            continue

        attr = mpdu[body_start:body_start + attr_len]
        if len(attr) < 9:
            return None
        service_control = attr[8]
        pos = 9
        if service_control & 0x40:  # Binding Bitmap
            pos += 2
        for present_bit in (0x04, 0x08):  # Matching Filter, Service Response Filter
            if service_control & present_bit:
                if pos >= len(attr):
                    return None
                pos += 1 + attr[pos]
        if not service_control & 0x10 or pos >= len(attr):  # no Service Info
            return None
        info_len = attr[pos]
        service_info = attr[pos + 1:pos + 1 + info_len]
        if repair_lengths and (info_len != nan_service_info_length(service_info) or len(service_info) < info_len):
            prescribed = nan_service_info_length(attr[pos + 1:])
            if prescribed is not None:
                service_info = attr[pos + 1:pos + 1 + prescribed]
        elif len(service_info) < info_len:
            return None
        if len(service_info) < 2:
            return None
        return service_info[0], service_info[1:]

    return None


def extract_ble_rid_payload(adv_data: bytes, repair_lengths: bool = False
                            ) -> Optional[Tuple[int, bytes, List[Dict[str, Any]], List[str]]]:
    """
    Unified ASTM F3411 Remote ID extractor for Bluetooth Low Energy advertising data.

    Used identically across all BLE capture engines (nRF sniffer subprocess, Linux HCI socket).
    Walks standard Bluetooth LTV (Length-Type-Value) structures to find:
      - AD Type 0x16 (Service Data - 16-bit UUID)
      - Service UUID 0xFFFA (little-endian: 0xFA, 0xFF)
      - Application Code 0x0D (ASTM F3411 / OpenDroneID)

    repair_lengths is for frames that failed their link-layer CRC: a Remote ID structure whose
    length byte is no length ASTM allows (ASTM_SERVICE_DATA_LENGTHS) or runs past the data is read
    with the length the structure's content prescribes (astm_service_data_length), cut to the data
    present. The CRC covers the length byte like the rest,
    so a corrupted one would otherwise lose the whole frame; its content may be corrupted too and
    is decoded as for any other corrupted frame (the caller flags it).

    Returns:
        (counter, astm_bytes, parsed_messages, messages_b64) or None if not an ASTM RID advertisement.
    """
    if not adv_data or len(adv_data) < 29:
        return None

    offset = 0
    total_len = len(adv_data)
    astm_data = None
    counter = 0

    while offset < total_len:
        ad_len = adv_data[offset]
        is_rid = (offset + 5 <= total_len and adv_data[offset + 1] == 0x16
                  and adv_data[offset + 2:offset + 4] == BLE_RID_UUID and adv_data[offset + 4] == APP_CODE_RID)
        if repair_lengths and is_rid and (ad_len not in ASTM_SERVICE_DATA_LENGTHS or offset + 1 + ad_len > total_len):
            prescribed = astm_service_data_length(adv_data, offset)
            if prescribed is not None:
                ad_len = min(prescribed, total_len - offset - 1)
        if ad_len == 0 or offset + 1 + ad_len > total_len:
            break
        ad_type = adv_data[offset + 1]
        ad_val = adv_data[offset + 2 : offset + 1 + ad_len]
        offset += 1 + ad_len

        # AD Type 0x16 = Service Data - 16-bit UUID
        if ad_type == 0x16 and len(ad_val) >= 4:
            if ad_val[:2] == BLE_RID_UUID:
                if ad_val[2] == APP_CODE_RID:
                    counter = ad_val[3]
                    astm_data = ad_val[4:]
                    break

    if astm_data is None or len(astm_data) < 25:
        return None

    parsed_messages, messages_b64 = parse_astm_payload(astm_data)
    if not parsed_messages:
        return None

    return counter, astm_data, parsed_messages, messages_b64
