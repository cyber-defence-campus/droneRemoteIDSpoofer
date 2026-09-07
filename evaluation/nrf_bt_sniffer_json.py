#!/usr/bin/env python3
"""
OTA Bluetooth Sniffer using nRF Sniffer (nrfutil ble-sniffer) with Real-Time JSON Output
Captures Bluetooth packets over the air, decodes ASTM F3411 Drone Remote ID broadcasts
when present, and streams structured JSON data directly to stdout.
Supports filtering by MAC address, Remote ID telemetry, and Bluetooth 5 Extended Advertising.
"""

import argparse
import json
import os
import signal
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

# Ensure repository root is in sys.path so sniffparser is importable from anywhere
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from sniffparser import ASTM_F3411_SpecParser

REMOTE_ID_UUID_BYTES = b"\xfa\xff"       # 16-bit UUID 0xFFFA in little-endian
BLE_ADV_ACCESS_ADDR = b"\xd6\xbe\x89\x8e" # Little-endian 0x8E89BED6

PDU_TYPE_MAP = {
    0x00: "ADV_IND",
    0x01: "ADV_DIRECT_IND",
    0x02: "ADV_NONCONN_IND",
    0x03: "SCAN_REQ",
    0x04: "SCAN_RSP",
    0x05: "CONNECT_REQ",
    0x06: "ADV_SCAN_IND",
    0x07: "ADV_EXT_IND/AUX_ADV_IND",
}

# Globals for clean teardown and statistics tracking
nrf_proc: Optional[subprocess.Popen] = None
fifo_created_path: Optional[str] = None
out_file_handle = None

mac_stats: Dict[str, Dict[str, Any]] = {}
total_packets_processed: int = 0
summary_printed: bool = False
group_by_mac_enabled: bool = False
stats_format_choice: str = "table"
pretty_json_choice: bool = False


def display_mac_stats(
    stats_format: str = "table",
    pretty: bool = False,
    clear_screen: bool = False,
    stream: Any = sys.stdout,
    is_final: bool = False
):
    global mac_stats, total_packets_processed
    if not mac_stats:
        return

    # Sort MAC addresses by frame count descending
    sorted_macs = sorted(mac_stats.items(), key=lambda item: item[1]["count"], reverse=True)

    if stats_format == "json" and (group_by_mac_enabled or is_final):
        out_dict = {}
        for mac, data in sorted_macs:
            try:
                first_seen_iso = datetime.fromtimestamp(data["first_seen"], timezone.utc).isoformat()
                last_seen_iso = datetime.fromtimestamp(data["last_seen"], timezone.utc).isoformat()
            except Exception:
                first_seen_iso = str(data["first_seen"])
                last_seen_iso = str(data["last_seen"])
            out_dict[mac] = {
                "frame_count": data["count"],
                "first_seen": round(data["first_seen"], 6),
                "last_seen": round(data["last_seen"], 6),
                "first_seen_iso": first_seen_iso,
                "last_seen_iso": last_seen_iso,
                "pdu_types": dict(data["pdu_types"]),
                "remote_id_transports": sorted(list(data["transports"])),
                "remote_id_messages": sorted(list(data["parsed_message_types"])),
                "rssi": {
                    "min": data["rssi_min"],
                    "max": data["rssi_max"],
                    "last": data["last_rssi"],
                } if data["last_rssi"] is not None else None
            }
        json_output = {
            "summary_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_packets": total_packets_processed,
            "unique_mac_count": len(mac_stats),
            "mac_statistics": out_dict
        }
        stream.write(json.dumps(json_output, indent=2 if pretty else None, default=str) + "\n")
        stream.flush()
        return

    # Table formatting
    if clear_screen and sys.stdout.isatty() and stream == sys.stdout:
        # Move cursor to top-left (home) and clear down to bottom of screen (preserves terminal scrollback buffer)
        stream.write("\033[H\033[J")

    latest_global_ts = max((d["last_seen"] for d in mac_stats.values()), default=0)

    title_prefix = "Final Capture" if is_final else "Live"
    header_line = f"[*] {title_prefix} MAC Statistics (Total Frames: {total_packets_processed} | Unique MACs: {len(mac_stats)})"
    sep_width = 112
    sep_heavy = "=" * sep_width + "\n"
    sep_light = "-" * sep_width + "\n"

    out_lines = [
        sep_heavy if not is_final else "",
        f"{header_line}\n",
        sep_heavy,
        f"{'MAC Address':<18} {'Frames':>7}  {'PDU Types':<32} {'Remote ID':<16} {'RSSI (min/max/last)':<21} {'Last Seen':>12}\n",
        sep_light
    ]
    if is_final:
        out_lines.insert(0, "\n" + sep_heavy)

    # In live mode, cap rows at 25 so table fits in terminal screen without causing continuous scrolling
    display_macs = sorted_macs if (is_final or len(sorted_macs) <= 25) else sorted_macs[:25]

    for mac, d in display_macs:
        count_str = str(d["count"])
        
        pdu_items = sorted(d["pdu_types"].items(), key=lambda x: x[1], reverse=True)
        pdu_strs = [f"{p}({c})" for p, c in pdu_items]
        pdu_combined = ", ".join(pdu_strs)
        if len(pdu_combined) > 31:
            pdu_combined = pdu_combined[:28] + "..."
            
        if len(d["transports"]) > 1:
            rid_str = "ble4 + ble5"
        elif d["transports"]:
            rid_str = next(iter(d["transports"]))
            if len(rid_str) > 16:
                rid_str = rid_str[:16]
        else:
            rid_str = "-"
            
        if d["last_rssi"] is not None:
            rssi_str = f"{d['rssi_min']} / {d['rssi_max']} / {d['last_rssi']} dBm"
        else:
            rssi_str = "-"
            
        diff = latest_global_ts - d["last_seen"]
        if 0 <= diff < 3600:
            seen_str = f"{diff:.1f}s ago"
        else:
            try:
                seen_str = datetime.fromtimestamp(d["last_seen"], timezone.utc).strftime("%H:%M:%S")
            except Exception:
                seen_str = f"{diff:.1f}s ago"

        out_lines.append(f"{mac:<18} {count_str:>7}  {pdu_combined:<32} {rid_str:<16} {rssi_str:<21} {seen_str:>12}\n")

    if not is_final and len(sorted_macs) > 25:
        out_lines.append(f"... and {len(sorted_macs) - 25} more MAC addresses (Press Ctrl+C for full summary)\n")

    out_lines.append(sep_light)
    stream.write("".join(out_lines))
    stream.flush()


def cleanup(signum=None, frame=None):
    global nrf_proc, fifo_created_path, out_file_handle, summary_printed, mac_stats, group_by_mac_enabled, stats_format_choice, pretty_json_choice
    if not summary_printed and mac_stats:
        summary_printed = True
        out_stream = sys.stdout if group_by_mac_enabled else sys.stderr
        display_mac_stats(stats_format=stats_format_choice, pretty=pretty_json_choice, clear_screen=False, stream=out_stream, is_final=True)

    if nrf_proc:
        sys.stderr.write("\n[*] Stopping nRF sniffer subprocess and process group...\n")
        try:
            # Kill entire process group to ensure nrfutil child plugin processes are terminated
            os.killpg(os.getpgid(nrf_proc.pid), signal.SIGTERM)
            time.sleep(0.2)
            os.killpg(os.getpgid(nrf_proc.pid), signal.SIGKILL)
        except Exception:
            try:
                nrf_proc.kill()
            except Exception:
                pass
        nrf_proc = None

    if out_file_handle:
        out_file_handle.close()
        out_file_handle = None

    if fifo_created_path and os.path.exists(fifo_created_path):
        try:
            os.remove(fifo_created_path)
        except OSError:
            pass

    sys.stderr.write("[*] Capture stopped.\n")
    sys.exit(0)


def parse_packet_metadata(data: bytes) -> Tuple[str, str, Optional[int], Optional[int]]:
    """
    Attempts to extract PDU type, Advertiser MAC address (AdvA), RSSI (dBm), and RF Channel from an nRF Sniffer packet.
    Follows Bluetooth Core Specification Vol 6 Part B §2.3.4 (Extended Advertising PDU) and §2.3.1 (Legacy PDU).
    """
    mac_address = "UNKNOWN"
    pdu_type_str = "UNKNOWN_OR_DATA"
    rssi_dbm = None
    rf_channel = None

    aa_idx = data.find(BLE_ADV_ACCESS_ADDR)
    if aa_idx != -1:
        # 1. Extract RSSI and RF Channel from Nordic Radio Header preceding Access Address
        # In nRF Sniffer v2/v3 (DLT_NORDIC_BLE / NRFS2_Packet / NRF2_Packet_Event):
        # Header layout:
        #   Board(1) + Len(2) + Ver(1) + Cnt(2) + Type(1) + HdrLen(1) + Flags(1) + Ch(1) + RSSI(1) + EvtCnt(2) + DeltaTime(4)
        # Access Address starts immediately after DeltaTime (aa_idx).
        # Therefore, relative to aa_idx:
        #   - RSSI is at offset (aa_idx - 7) (e.g. Offset 10 when Board is present, aa_idx=17)
        #   - RF Channel is at offset (aa_idx - 8) (e.g. Offset 9 when Board is present, aa_idx=17)
        if aa_idx >= 7:
            raw_rssi = data[aa_idx - 7]
            if 10 <= raw_rssi <= 120:
                rssi_dbm = -int(raw_rssi)
            elif 136 <= raw_rssi <= 246:  # signed -120 to -10 (0x88 to 0xF6)
                rssi_dbm = int(raw_rssi - 256)
            elif -120 <= raw_rssi <= -10:
                rssi_dbm = int(raw_rssi)

        if aa_idx >= 8:
            ch_val = data[aa_idx - 8]
            if 0 <= ch_val <= 39:
                rf_channel = int(ch_val)

        # 2. Extract PDU Type & MAC Address following Access Address
        if len(data) >= aa_idx + 6:
            pdu_type = data[aa_idx + 4] & 0x0F
            pdu_type_str = PDU_TYPE_MAP.get(pdu_type, f"PDU_{pdu_type:02X}")
            payload = data[aa_idx + 6 :]

            if pdu_type == 0x07:
                pdu_type_str = "ADV_EXT_IND/AUX_ADV_IND"
                # Bluetooth Core Spec Vol 6 Part B §2.3.4:
                # Byte 0 of payload: Extended Header Length (bits 0-5) | AdvMode (bits 6-7)
                if len(payload) >= 1:
                    ext_hdr_len = payload[0] & 0x3F
                    if ext_hdr_len > 0 and len(payload) >= 1 + ext_hdr_len:
                        ext_hdr = payload[1 : 1 + ext_hdr_len]
                        flags = ext_hdr[0]
                        # Bit 0 (0x01) of Extended Header Flags indicates AdvA is present (6 bytes)
                        if (flags & 0x01) and len(ext_hdr) >= 7:
                            mac_bytes = ext_hdr[1:7]
                            mac_address = ":".join(f"{b:02X}" for b in reversed(mac_bytes))
            else:
                # Legacy PDU types: ADV_IND(0), ADV_DIRECT_IND(1), ADV_NONCONN_IND(2), SCAN_RSP(4), ADV_SCAN_IND(6)
                if pdu_type in (0x00, 0x01, 0x02, 0x04, 0x06):
                    if len(payload) >= 6:
                        mac_bytes = payload[0:6]
                        mac_address = ":".join(f"{b:02X}" for b in reversed(mac_bytes))

    return pdu_type_str, mac_address, rssi_dbm, rf_channel


def extract_remote_id_info(data: bytes, pdu_type_str: str) -> Optional[Dict[str, Any]]:
    """
    Extracts ASTM F3411 Remote ID information from raw packet bytes.
    Traverses Bluetooth AD structures (Length-Type-Value) in the advertising payload
    to avoid false-positive offset shifts from header or coordinate byte collisions.
    """
    # 1. Identify Advertising Data (AdvData) slice
    adv_data = None
    aa_idx = data.find(BLE_ADV_ACCESS_ADDR)
    if aa_idx != -1 and len(data) >= aa_idx + 6:
        pdu_type = data[aa_idx + 4] & 0x0F
        payload = data[aa_idx + 6 :]
        if pdu_type == 0x07:
            if len(payload) >= 1:
                ext_hdr_len = payload[0] & 0x3F
                adv_data = payload[1 + ext_hdr_len :]
        elif pdu_type in (0x00, 0x01, 0x02, 0x04, 0x06):
            if len(payload) >= 6:
                adv_data = payload[6:]

    counter = 0
    astm_data = None

    # 2. Structured AD Structure Traversal (Standard Bluetooth LTV format)
    if adv_data:
        offset = 0
        total_len = len(adv_data)
        while offset < total_len:
            ad_len = adv_data[offset]
            if ad_len == 0:
                break
            if offset + 1 + ad_len > total_len:
                break
            ad_type = adv_data[offset + 1]
            ad_val = adv_data[offset + 2 : offset + 1 + ad_len]
            offset += 1 + ad_len

            # AD Type 0x16 = Service Data - 16-bit UUID
            if ad_type == 0x16 and len(ad_val) >= 2:
                # UUID 0xFFFA (Little-Endian: \xfa\xff)
                if ad_val[:2] == REMOTE_ID_UUID_BYTES:
                    svc_payload = ad_val[2:]
                    if len(svc_payload) >= 2 and svc_payload[0] == 0x0D:
                        counter = svc_payload[1]
                        astm_data = svc_payload[2:]
                    else:
                        counter = 0
                        astm_data = svc_payload
                    break

    # 3. Robust Fallback if not found via strict LTV traversal
    if astm_data is None:
        # Fallback A: Search for AD Type 0x16 + UUID 0xFFFA + AppCode 0x0D
        marker_16 = b"\x16\xfa\xff\x0d"
        idx = data.find(marker_16)
        if idx != -1 and len(data) >= idx + 5:
            counter = data[idx + 4]
            astm_data = data[idx + 5 :]
        else:
            # Fallback B: Search for UUID 0xFFFA + AppCode 0x0D
            marker_uuid = b"\xfa\xff\x0d"
            idx = data.find(marker_uuid)
            if idx != -1 and len(data) >= idx + 4:
                counter = data[idx + 3]
                astm_data = data[idx + 4 :]
            else:
                # Fallback C: Generic UUID search
                idx = data.find(REMOTE_ID_UUID_BYTES)
                if idx != -1:
                    payload_after_uuid = data[idx + len(REMOTE_ID_UUID_BYTES) :]
                    if len(payload_after_uuid) >= 2 and payload_after_uuid[0] == 0x0D:
                        counter = payload_after_uuid[1]
                        astm_data = payload_after_uuid[2:]
                    else:
                        counter = 0
                        astm_data = payload_after_uuid

    if astm_data is None or len(astm_data) < 25:
        return None

    # Distinguish BLE 4 Legacy vs BLE 5 Extended Advertising
    msg_type = (astm_data[0] >> 4) if len(astm_data) > 0 else None
    if (
        msg_type == 0xF
        or len(astm_data) > 30
        or pdu_type_str in ("ADV_EXT_IND/AUX_ADV_IND", "PDU_07")
        or pdu_type_str.startswith("ADV_EXT")
        or pdu_type_str.startswith("AUX_")
    ):
        transport = "ble5_extended"
    elif pdu_type_str in ("ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "ADV_SCAN_IND", "SCAN_RSP"):
        transport = "ble4_legacy"
    else:
        transport = "ble4_legacy"

    parser = ASTM_F3411_SpecParser(astm_data)
    try:
        parsed_messages = parser.parse_payload()
    except Exception as e:
        parsed_messages = [{"type": "ParserError", "error": str(e)}]

    if not parsed_messages:
        return None

    return {
        "transport": transport,
        "counter": counter,
        "parsed_messages": parsed_messages
    }



def process_packet(
    data: bytes,
    ts: float,
    pretty: bool = False,
    only_rid: bool = False,
    only_bt5: bool = False,
    filter_mac: Optional[str] = None,
    filter_mac_bytes_le: Optional[bytes] = None,
    filter_mac_bytes_be: Optional[bytes] = None,
    group_by_mac: bool = False
):
    """
    Processes raw link-layer bytes, decodes any present Remote ID ASTM payloads,
    filters by MAC address, BT5 extended advertising, or Remote ID if specified,
    and streams as a formatted JSON object.
    """
    if not data:
        return

    pdu_type_str, mac_address, rssi_dbm, rf_channel = parse_packet_metadata(data)

    # Apply MAC address filtering (checks parsed MAC and raw link-layer bytes in header)
    if filter_mac:
        match_found = False
        if mac_address and mac_address.upper() == filter_mac.upper():
            match_found = True
        elif filter_mac_bytes_le and filter_mac_bytes_le in data:
            match_found = True
            if mac_address == "UNKNOWN":
                mac_address = filter_mac.upper()
        elif filter_mac_bytes_be and filter_mac_bytes_be in data:
            match_found = True
            if mac_address == "UNKNOWN":
                mac_address = filter_mac.upper()

        if not match_found:
            return

    remote_id_info = extract_remote_id_info(data, pdu_type_str)

    # If --only-rid flag was given and no Remote ID payload was detected, ignore this packet
    if only_rid and not remote_id_info:
        return

    # If --only-bt5 flag was given, filter out non-BT5 packets (allow any ble5_extended transport or BT5 PDU type)
    if only_bt5:
        is_bt5_transport = (remote_id_info and remote_id_info.get("transport") == "ble5_extended")
        is_bt5_pdu = (pdu_type_str in ("ADV_EXT_IND/AUX_ADV_IND", "PDU_07") or pdu_type_str.startswith("ADV_EXT") or pdu_type_str.startswith("AUX_"))
        if not (is_bt5_transport or is_bt5_pdu):
            return

    # Update global MAC statistics
    global mac_stats, total_packets_processed
    total_packets_processed += 1
    if mac_address not in mac_stats:
        mac_stats[mac_address] = {
            "count": 0,
            "first_seen": ts,
            "last_seen": ts,
            "pdu_types": {},
            "transports": set(),
            "parsed_message_types": set(),
            "rssi_min": rssi_dbm,
            "rssi_max": rssi_dbm,
            "last_rssi": rssi_dbm
        }

    stats = mac_stats[mac_address]
    stats["count"] += 1
    if ts > stats["last_seen"]:
        stats["last_seen"] = ts
    if ts < stats["first_seen"]:
        stats["first_seen"] = ts
    stats["pdu_types"][pdu_type_str] = stats["pdu_types"].get(pdu_type_str, 0) + 1
    if rssi_dbm is not None:
        stats["last_rssi"] = rssi_dbm
        if stats["rssi_min"] is None or rssi_dbm < stats["rssi_min"]:
            stats["rssi_min"] = rssi_dbm
        if stats["rssi_max"] is None or rssi_dbm > stats["rssi_max"]:
            stats["rssi_max"] = rssi_dbm
    if remote_id_info:
        if "transport" in remote_id_info:
            stats["transports"].add(remote_id_info["transport"])
        for msg in remote_id_info.get("parsed_messages", []):
            if isinstance(msg, dict) and "type" in msg:
                stats["parsed_message_types"].add(msg["type"])

    # Construct complete JSON record for every captured packet
    record: Dict[str, Any] = {
        "timestamp": round(ts, 6),
        "timestamp_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
        "pdu_type": pdu_type_str,
        "mac": mac_address,
        "rf_channel": rf_channel,
        "rssi_dbm": rssi_dbm,
        "raw_length": len(data),
        "raw_hex": data.hex().upper(),
        "remote_id": remote_id_info
    }

    if not group_by_mac:
        # Print JSON record directly to stdout in per-packet stream mode
        json_str = json.dumps(record, indent=2 if pretty else None, default=str)
        print(json_str)
        sys.stdout.flush()

    if out_file_handle:
        out_file_handle.write(json.dumps(record, default=str) + "\n")
        out_file_handle.flush()


def run_sniffer(
    pcap_path: str,
    nrf_port: Optional[str] = None,
    pretty: bool = False,
    only_rid: bool = False,
    only_bt5: bool = False,
    filter_mac: Optional[str] = None,
    coded_phy: bool = False,
    group_by_mac: bool = False,
    stats_format: str = "table",
    stats_interval: float = 2.0
):
    global nrf_proc, fifo_created_path

    filter_mac_bytes_le = None
    filter_mac_bytes_be = None
    if filter_mac:
        filter_mac = filter_mac.replace("-", ":").upper()
        try:
            clean_hex = filter_mac.replace(":", "").replace("-", "")
            if len(clean_hex) == 12:
                filter_mac_bytes_be = bytes.fromhex(clean_hex)
                filter_mac_bytes_le = filter_mac_bytes_be[::-1]
        except ValueError:
            sys.stderr.write(f"[!] Warning: Could not parse MAC {filter_mac} into raw bytes; relying only on header decoding.\n")

    if nrf_port:
        if not os.path.exists(nrf_port):
            import glob
            alt_ports = glob.glob("/dev/ttyACM*") + glob.glob("/dev/ttyUSB*")
            if alt_ports:
                sys.stderr.write(f"[!] Warning: Specified port {nrf_port} not found! Automatically switching to available serial port: {alt_ports[0]}\n")
                nrf_port = alt_ports[0]

        if os.path.exists(pcap_path):
            try:
                os.remove(pcap_path)
            except OSError:
                pass

        sys.stderr.write(f"[*] Creating FIFO named pipe at {pcap_path}...\n")
        try:
            os.mkfifo(pcap_path)
            fifo_created_path = pcap_path
        except OSError as e:
            sys.stderr.write(f"[!] Warning: Could not create FIFO at {pcap_path}: {e}\n")

        nrf_cmd = [
            "nrfutil", "ble-sniffer", "sniff", "--only-advertising",
            "--port", nrf_port,
            "--output-pcap-file", pcap_path,
            "--scan-follow-aux",
            "--scan-follow-aux-chain"
        ]
        if filter_mac:
            nrf_cmd.extend(["--follow", filter_mac])
        if coded_phy or only_bt5:
            nrf_cmd.append("--coded")

        sys.stderr.write(f"[*] Launching nRF sniffer process on {nrf_port}: {' '.join(nrf_cmd)}\n")
        try:
            nrf_proc = subprocess.Popen(nrf_cmd, stderr=sys.stderr, start_new_session=True)
        except FileNotFoundError:
            sys.stderr.write("[-] Error: 'nrfutil' command not found in PATH. Please install nrfutil and ble-sniffer plugin.\n")
            cleanup()
            return
        time.sleep(1.0)
    else:
        sys.stderr.write(f"[*] Reading BLE PCAP stream from {pcap_path}...\n")

    mode_parts = []
    if only_rid:
        mode_parts.append("Remote ID")
    if only_bt5:
        mode_parts.append("BT5 Extended Advertising")
    mode_desc = (" ONLY " + " & ".join(mode_parts) + " packets") if mode_parts else " ALL captured Bluetooth packets"
    mac_desc = f" from MAC {filter_mac}" if filter_mac else ""
    output_mode_desc = f"grouped MAC statistics ({stats_format})" if group_by_mac else "JSON stream"
    
    sys.stderr.write(f"[*] Listening and displaying{mode_desc}{mac_desc} as {output_mode_desc}... (Press Ctrl+C to stop)\n\n")

    f = None
    try:
        # Wait for the file/FIFO to become available and readable
        while True:
            if os.path.exists(pcap_path):
                try:
                    f = open(pcap_path, "rb")
                    break
                except Exception:
                    time.sleep(0.1)
            else:
                time.sleep(0.2)
                if nrf_port and (not nrf_proc or nrf_proc.poll() is not None):
                    sys.stderr.write("[-] Error: nrfutil subprocess terminated unexpectedly.\n")
                    cleanup()
                    return

        # Read 24-byte Global PCAP Header manually to avoid third-party PCAP library compatibility errors
        hdr = f.read(24)
        if len(hdr) < 24:
            sys.stderr.write("[-] Error: Invalid or truncated PCAP global header.\n")
            cleanup()
            return

        magic, major, minor, tz, sig, snaplen, network = struct.unpack("<IHHiIII", hdr)
        # Determine byte order (default to little-endian if standard magic numbers don't match exactly)
        endian = ">" if magic in (0xd4c3b2a1, 0x4d3cb2a1) else "<"
        
        linktype_clean = network & 0xFFFF
        flags_clean = network >> 16
        sys.stderr.write(f"[*] PCAP stream synchronized (linktype={linktype_clean}, flags=0x{flags_clean:04X}, endian={'little' if endian=='<' else 'big'}). Streaming JSON output:\n\n")

        # Continuously process packets from PCAP stream
        last_display_time = 0.0
        while True:
            pkthdr = f.read(16)
            if not pkthdr or len(pkthdr) < 16:
                if group_by_mac and sys.stdout.isatty() and time.time() - last_display_time >= stats_interval and mac_stats:
                    display_mac_stats(stats_format=stats_format, pretty=pretty, clear_screen=True, stream=sys.stdout, is_final=False)
                    last_display_time = time.time()
                if nrf_port and (not nrf_proc or nrf_proc.poll() is not None):
                    break
                try:
                    import stat
                    if not nrf_port and os.path.exists(pcap_path) and not stat.S_ISFIFO(os.stat(pcap_path).st_mode):
                        break
                except Exception:
                    break
                time.sleep(0.01)
                continue

            ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkthdr)
            if incl_len > 65535:
                # Corrupted or desynchronized length header, attempt recovery
                continue

            data = f.read(incl_len)
            while len(data) < incl_len:
                if nrf_port and (not nrf_proc or nrf_proc.poll() is not None):
                    break
                time.sleep(0.005)
                more = f.read(incl_len - len(data))
                if more:
                    data += more
                else:
                    time.sleep(0.01)
            if len(data) < incl_len:
                break

            ts = ts_sec + (ts_usec / 1e6)
            process_packet(
                data, ts,
                pretty=pretty,
                only_rid=only_rid,
                only_bt5=only_bt5,
                filter_mac=filter_mac,
                filter_mac_bytes_le=filter_mac_bytes_le,
                filter_mac_bytes_be=filter_mac_bytes_be,
                group_by_mac=group_by_mac
            )
            if group_by_mac and sys.stdout.isatty() and time.time() - last_display_time >= stats_interval and mac_stats:
                display_mac_stats(stats_format=stats_format, pretty=pretty, clear_screen=True, stream=sys.stdout, is_final=False)
                last_display_time = time.time()

    except KeyboardInterrupt:
        pass
    except Exception as e:
        sys.stderr.write(f"[-] Uncaught exception during capture: {e}\n")
    finally:
        if f:
            f.close()
        cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="OTA Bluetooth Sniffer using nRF Sniffer with Real-Time JSON Output",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-p", "--nrf-port",
        help="Serial port for Nordic nRF sniffer dongle (e.g. /dev/ttyACM0). Simultaneously starts nrfutil ble-sniffer."
    )
    parser.add_argument(
        "-f", "--rx-pcap",
        default="./nrf_capture.fifo",
        help="Path to PCAP file or FIFO named pipe to read captured BLE packets from"
    )
    parser.add_argument(
        "-m", "--filter-mac",
        help="Filter captured packets by advertiser MAC address (case-insensitive, e.g. 3c:dc:75:9b:1e:d6)"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output with indentation instead of compact JSON Lines"
    )
    parser.add_argument(
        "--only-rid",
        action="store_true",
        help="Only output packets that contain ASTM F3411 Drone Remote ID service data"
    )
    parser.add_argument(
        "-b", "--only-bt5", "--bt5", "--bt5-only", "--only-extended",
        dest="only_bt5",
        action="store_true",
        help="Only output Bluetooth 5 Extended Advertising packets (PDU type 0x07 ADV_EXT_IND/AUX_ADV_IND or message packs)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output JSONL file path to record captured records while printing to stdout"
    )
    parser.add_argument(
        "-g", "--group-by-mac", "--stats",
        dest="group_by_mac",
        action="store_true",
        help="Group outputs by sender MAC address showing frame counts, PDU types, and Remote ID info instead of per-packet stream"
    )
    parser.add_argument(
        "--coded",
        action="store_true",
        help="Instruct nRF Sniffer to scan and follow LE Coded PHY (Bluetooth 5 Long Range S=8 / S=2)"
    )
    parser.add_argument(
        "--stats-format",
        choices=["table", "json"],
        default="table",
        help="Output format for MAC statistics when using --group-by-mac (default: table)"
    )
    parser.add_argument(
        "--stats-interval",
        type=float,
        default=2.0,
        help="Refresh interval in seconds for live table display when using --group-by-mac in a terminal"
    )

    args = parser.parse_args()

    global group_by_mac_enabled, stats_format_choice, pretty_json_choice
    group_by_mac_enabled = args.group_by_mac
    stats_format_choice = args.stats_format
    pretty_json_choice = args.pretty

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    global out_file_handle
    if args.output:
        try:
            out_file_handle = open(args.output, "a")
            sys.stderr.write(f"[*] Replay logs will also be written to {args.output}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Failed to open output file {args.output}: {e}\n")
            sys.exit(1)

    run_sniffer(
        pcap_path=args.rx_pcap,
        nrf_port=args.nrf_port,
        pretty=args.pretty,
        only_rid=args.only_rid,
        only_bt5=args.only_bt5,
        filter_mac=args.filter_mac,
        coded_phy=args.coded,
        group_by_mac=args.group_by_mac,
        stats_format=args.stats_format,
        stats_interval=args.stats_interval
    )


if __name__ == "__main__":
    main()
