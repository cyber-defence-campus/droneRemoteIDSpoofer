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
import struct
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

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
    0x1: "Emergency Status (v2)",
    0x2: "Extended Status (v2)",
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


def sanitize_ascii_string(data: bytes, max_len: int = 25) -> str:
    """Sanitize ASCII string removing non-printable and control bytes."""
    cleaned = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', data[:max_len].decode('ascii', errors='ignore')).strip()
    return cleaned


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

    result: Dict[str, Any] = {
        "msg_type": msg_type,
        "type": MSG_TYPE_NAMES.get(msg_type, f"Unknown ({msg_type})"),
        "protocol_version": proto_ver,
        "proto_version_name": PROTO_VERSION_NAMES.get(proto_ver, f"Version {proto_ver}"),
        "raw_hex": block[:25].hex().upper(),
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
                direction_deg = None

            speed_raw = block[3]
            if speed_raw == 255 and speed_mult == 0:
                speed_mps = None
            else:
                speed_mps = (speed_raw * 0.25) if speed_mult == 0 else (63.75 + speed_raw * 0.75)

            v_speed_raw = struct.unpack('<b', block[4:5])[0]
            v_speed_mps = None if v_speed_raw == 63 else (v_speed_raw * 0.5)

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
                "heading": direction_deg,
                "speed_mps": round(speed_mps, 2) if speed_mps is not None else None,
                "speed": round(speed_mps, 2) if speed_mps is not None else None,
                "vertical_speed_mps": round(v_speed_mps, 2) if v_speed_mps is not None else None,
                "lat": lat,
                "lon": lon,
                "pressure_altitude_m": round(p_alt_m, 2) if p_alt_m is not None else None,
                "geodetic_altitude_m": round(g_alt_m, 2) if g_alt_m is not None else None,
                "alt": round(g_alt_m or p_alt_m or 0.0, 2) if (g_alt_m or p_alt_m) else None,
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
                "desc_type_name": DESC_TYPE_NAMES.get(desc_type, f"Reserved ({desc_type})"),
                "description": desc,
                "desc": desc,
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


class ASTM_F3411_SpecParser:
    """Universal ASTM F3411 Parser Class compatible with all sniffers and evaluation scripts."""
    def __init__(self, raw_bytes: bytes):
        self.data = raw_bytes

    def parse_payload(self) -> List[Dict[str, Any]]:
        results, _ = parse_astm_payload(self.data)
        return results


# --- Scapy Sniffer Logic (Lazy Import) ---

def packet_callback(pkt):
    from scapy.all import Dot11Beacon, Dot11Elt
    if pkt.haslayer(Dot11Beacon):
        elt = pkt.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            if elt.ID == 221 and elt.info.startswith(b'\xfa\x0b\xbc'):
                astm_payload = elt.info[5:]
                try:
                    parser = ASTM_F3411_SpecParser(astm_payload)
                    data = parser.parse_payload()
                    if data:
                        chan_info = ""
                        if pkt.haslayer("RadioTap"):
                            try:
                                freq = pkt.getlayer("RadioTap").ChannelFrequency
                                if freq == 2484: chan = 14
                                elif freq < 2484: chan = (freq - 2407) // 5
                                elif freq > 5000: chan = (freq - 5000) // 5
                                else: chan = freq
                                chan_info = f", Ch: {chan}"
                            except Exception:
                                pass
                        print(f"\n[+] Remote ID Detected from {pkt.addr2} (RSSI: {pkt.dBm_AntSignal}dBm{chan_info})")
                        for entry in data:
                            print(f"    - {entry}")
                except Exception:
                    pass
            elt = elt.payload


if __name__ == "__main__":
    from scapy.all import sniff
    interface = "wlx40ae30abad23"
    print(f"[*] Starting Remote ID Scanner on {interface}...")
    sniff(iface=interface, prn=packet_callback, store=0)