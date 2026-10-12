#!/usr/bin/env python3
"""
OTA Bluetooth Sniffer using nRF Sniffer (nrfutil ble-sniffer) with Real-Time JSON Output
Captures Bluetooth packets over the air, decodes ASTM F3411 Drone Remote ID broadcasts
when present, and streams structured JSON data directly to stdout.
Supports filtering by MAC address, Remote ID telemetry, and Bluetooth 5 Extended Advertising.
"""

import argparse
import glob
import json
import os
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

def build_pcap_record_header(ts: float, pkt_len: int) -> bytes:
    """Builds a standard 16-byte libpcap packet record header (little-endian)."""
    ts_sec = int(ts)
    ts_usec = int(round((ts - ts_sec) * 1_000_000))
    if ts_usec >= 1_000_000:
        ts_sec += 1
        ts_usec -= 1_000_000
    return struct.pack("<IIII", ts_sec, ts_usec, pkt_len, pkt_len)


# Ensure repository root is in sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from drone_rid_spoofer.parser import extract_ble_rid_payload, is_valid_timestamp, parse_astm_payload

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
hopper_controller = None
fifo_created_path: Optional[str] = None
out_file_handle = None

mac_stats: Dict[str, Dict[str, Any]] = {}
total_packets_processed: int = 0
summary_printed: bool = False
group_by_mac_enabled: bool = False
stats_format_choice: str = "table"
pretty_json_choice: bool = False


class BleModeHopperController:
    """
    Manages the nrfutil ble-sniffer subprocess lifecycle, supporting dynamic
    Time-Division Multiplexing (TDM) hopping between BT5 (Extended + Coded) and BT4 (Legacy).
    """
    def __init__(
        self,
        nrf_port: str,
        pcap_path: str,
        mode: str = "hop",
        bt5_dwell_s: float = 5.0,
        bt4_dwell_s: float = 1.0,
        filter_mac: Optional[str] = None,
    ):
        self.nrf_port = nrf_port
        self.pcap_path = pcap_path
        self.mode = mode
        self.bt5_dwell_s = max(0.1, bt5_dwell_s)
        self.bt4_dwell_s = max(0.1, bt4_dwell_s)
        self.filter_mac = filter_mac
        self.running = False
        self.current_mode = "bt5" if mode in ("hop", "extended", "bt5") else ("bt4" if mode in ("legacy", "bt4") else "all")
        self.proc: Optional[subprocess.Popen] = None
        self.thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

    def _get_cmd_for_mode(self, mode: str) -> List[str]:
        cmd = ["nrfutil", "ble-sniffer", "sniff", "--port", self.nrf_port, "--output-pcap-file", self.pcap_path]
        if mode == "bt4":
            cmd.append("--only-legacy_advertising")
        elif mode == "bt5":
            cmd.extend([
                "--only-advertising",
                "--scan-follow-aux",
                "--scan-follow-aux-chain",
                "--coded"
            ])
        else:  # "all"
            cmd.extend([
                "--only-advertising",
                "--scan-follow-aux",
                "--scan-follow-aux-chain",
                "--coded"
            ])

        if self.filter_mac:
            cmd.extend(["--follow", self.filter_mac])
        return cmd

    def _run_loop(self):
        if self.mode != "hop":
            # Non-hopping mode: spawn once and supervise until stopped
            cmd = self._get_cmd_for_mode(self.current_mode)
            try:
                with self._lock:
                    sys.stderr.write(f"[{self.current_mode}] Spawning nrfutil with command: {' '.join(cmd)}\n")
                    sys.stderr.flush()
                    self.proc = subprocess.Popen(
                        cmd,
                        stderr=subprocess.PIPE,
                        start_new_session=True
                    )
            except FileNotFoundError:
                sys.stderr.write("[-] Error: 'nrfutil' command not found in PATH. Please install nrfutil and ble-sniffer plugin.\n")
                self.running = False
                return
            except Exception as e:
                sys.stderr.write(f"[-] Error launching nrfutil ({self.current_mode}): {e}\n")
                self.running = False
                return

            while self.running:
                ret = self.proc.poll()
                if ret is not None:
                    # Process died unexpectedly
                    err_out = ""
                    if self.proc.stderr:
                        try:
                            err_out = self.proc.stderr.read().decode('utf-8', errors='replace').strip()
                        except Exception:
                            pass
                    sys.stderr.write(f"[-] Error: nrfutil ({self.current_mode}) exited unexpectedly with code {ret}!\n")
                    if err_out:
                        sys.stderr.write(f"[-] nrfutil stderr:\n{err_out}\n")
                    sys.stderr.flush()
                    self.running = False
                    break
                time.sleep(0.05)

            self.stop_proc()
            return

        # Hopping mode: dynamic TDM switching between BT5 and BT4
        consecutive_failures = 0
        while self.running:
            cmd = self._get_cmd_for_mode(self.current_mode)
            try:
                with self._lock:
                    sys.stderr.write(f"[{self.current_mode}] Spawning nrfutil with command: {' '.join(cmd)}\n")
                    sys.stderr.flush()
                    self.proc = subprocess.Popen(
                        cmd,
                        stderr=subprocess.PIPE,
                        start_new_session=True
                    )
            except FileNotFoundError:
                sys.stderr.write("[-] Error: 'nrfutil' command not found in PATH. Please install nrfutil and ble-sniffer plugin.\n")
                self.running = False
                break
            except Exception as e:
                sys.stderr.write(f"[-] Error launching nrfutil ({self.current_mode}): {e}\n")
                time.sleep(1.0)
                continue

            dwell = self.bt5_dwell_s if self.current_mode == "bt5" else self.bt4_dwell_s
            t_start = time.time()
            died_early = False

            while self.running and (time.time() - t_start) < dwell:
                ret = self.proc.poll()
                if ret is not None:
                    err_out = ""
                    if self.proc.stderr:
                        try:
                            err_out = self.proc.stderr.read().decode('utf-8', errors='replace').strip()
                        except Exception:
                            pass
                    sys.stderr.write(f"[-] Error: nrfutil ({self.current_mode}) exited unexpectedly with code {ret}!\n")
                    if err_out:
                        sys.stderr.write(f"[-] nrfutil stderr:\n{err_out}\n")
                    sys.stderr.flush()
                    died_early = True
                    break
                time.sleep(0.05)

            if not self.running:
                self.stop_proc()
                break

            if died_early:
                consecutive_failures += 1
                self.stop_proc()
                if consecutive_failures >= 3:
                    sys.stderr.write("[-] Error: nrfutil crashed repeatedly in hopping mode. Stopping sniffer.\n")
                    self.running = False
                    break
                time.sleep(1.0)
            else:
                consecutive_failures = 0
                self.stop_proc()
                time.sleep(0.15)  # allow USB serial / CDC-ACM port to settle

            # Switch mode
            self.current_mode = "bt4" if self.current_mode == "bt5" else "bt5"

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._run_loop, name="BleModeHopperController", daemon=True)
        self.thread.start()

    def stop_proc(self):
        with self._lock:
            if self.proc:
                if self.proc.poll() is None:
                    try:
                        os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
                        for _ in range(10):
                            if self.proc.poll() is not None:
                                break
                            time.sleep(0.02)
                        if self.proc.poll() is None:
                            os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                    except Exception:
                        try:
                            self.proc.kill()
                        except Exception:
                            pass
                    try:
                        self.proc.wait(timeout=0.3)
                    except Exception:
                        pass
                if self.proc.stderr and not self.proc.stderr.closed:
                    try:
                        self.proc.stderr.close()
                    except Exception:
                        pass
                self.proc = None

    def stop(self):
        self.running = False
        self.stop_proc()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=0.5)


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
    global nrf_proc, hopper_controller, fifo_created_path, out_file_handle, summary_printed, mac_stats, group_by_mac_enabled, stats_format_choice, pretty_json_choice
    if not summary_printed and mac_stats:
        summary_printed = True
        out_stream = sys.stdout if group_by_mac_enabled else sys.stderr
        display_mac_stats(stats_format=stats_format_choice, pretty=pretty_json_choice, clear_screen=False, stream=out_stream, is_final=True)

    if hopper_controller:
        hopper_controller.stop()
        hopper_controller = None

    if nrf_proc:
        sys.stderr.write("\n[*] Stopping nRF sniffer subprocess and process group...\n")
        try:
            os.killpg(os.getpgid(nrf_proc.pid), signal.SIGTERM)
            time.sleep(0.1)
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


def locate_ble_packet(data: bytes) -> Tuple[int, int, Optional[int], Optional[int]]:
    """
    Locates the 4-byte Access Address offset, PDU header offset, RF Channel, and RSSI
    within a DLT 272 (DLT_NORDIC_BLE) packet.
    Handles both Primary Advertising Channels (fixed AA 0x8E89BED6) and
    Secondary Advertising Channels (pseudo-random AA for AUX_ADV_IND / Coded PHY).
    Also detects LE Coded PHY (which inserts a 1-byte Coding Indicator between AA and PDU).
    Returns: (aa_idx, pdu_offset, rf_channel, rssi_dbm). If no valid BLE packet found, returns (-1, -1, None, None).
    """
    rf_channel = None
    rssi_dbm = None
    aa_idx = -1

    # 1. Primary Advertising Channels (37, 38, 39) with standard fixed Access Address
    found_aa = data.find(BLE_ADV_ACCESS_ADDR)
    if found_aa != -1:
        aa_idx = found_aa
    elif len(data) >= 23:
        # 2. Secondary Advertising Channels (0-36) where Access Address is pseudo-random (AUX_ADV_IND, AUX_CHAIN_IND)
        # In Nordic DLT 272 (DLT_NORDIC_BLE):
        # Header: Board(1) + Len(2) + Ver(1) + Cnt(2) + Type(1) + EventHdrLen(1) + Flags(1) + Ch(1) + RSSI(1) + EvtCnt(2) + Time(4)
        # EventHdrLen at data[7] is typically 10 (or 6 in older firmware), placing AA at offset 17 (7 + 10).
        hdr_len_remaining = data[7] if len(data) > 7 else 0
        candidate_aa_idx = 7 + hdr_len_remaining if hdr_len_remaining in (6, 10) else 17
        if len(data) >= candidate_aa_idx + 6:
            aa_idx = candidate_aa_idx

    if aa_idx == -1:
        return -1, -1, None, None

    # Extract RSSI and RF Channel from Nordic header if present
    if aa_idx >= 7:
        raw_rssi = data[aa_idx - 7]
        if 10 <= raw_rssi <= 120:
            rssi_dbm = -int(raw_rssi)
        elif 136 <= raw_rssi <= 246:
            rssi_dbm = int(raw_rssi - 256)
        elif -120 <= raw_rssi <= -10:
            rssi_dbm = int(raw_rssi)

    if aa_idx >= 8:
        ch_val = data[aa_idx - 8]
        if 0 <= ch_val <= 39:
            rf_channel = int(ch_val)

    # Determine PDU header offset:
    # On LE Coded PHY (Nordic flags PHY field == 2, or CI byte followed by PDU 0x07),
    # there is a 1-byte Coding Indicator (CI) between the 4-byte AA and PDU header.
    is_coded = False
    if aa_idx >= 9:
        flags = data[aa_idx - 9]
        phy = (flags >> 4) & 0x07
        if phy == 2:  # LE_CODED_PHY
            is_coded = True

    # Cross-check: if candidate at aa_idx + 5 has PDU type 0x07 (ADV_EXT_IND/AUX_ADV_IND)
    # and byte at aa_idx + 4 is a CI indicator (0x00, 0x01, 0x02, 0x03)
    if not is_coded and len(data) >= aa_idx + 6:
        if data[aa_idx + 4] in (0x00, 0x01, 0x02, 0x03) and (data[aa_idx + 5] & 0x0F) == 0x07:
            is_coded = True

    pdu_offset = aa_idx + 5 if is_coded else aa_idx + 4

    # Validate that pdu_offset points to a valid PDU
    if len(data) >= pdu_offset + 2:
        pdu_type = data[pdu_offset] & 0x0F
        if pdu_type in PDU_TYPE_MAP:
            return aa_idx, pdu_offset, rf_channel, rssi_dbm

    # Fallback: if pdu_offset validation failed but aa_idx + 4 is in PDU_TYPE_MAP
    if len(data) >= aa_idx + 6:
        alt_pdu_type = data[aa_idx + 4] & 0x0F
        if alt_pdu_type in PDU_TYPE_MAP:
            return aa_idx, aa_idx + 4, rf_channel, rssi_dbm

    return aa_idx, pdu_offset, rf_channel, rssi_dbm


def parse_packet_metadata(data: bytes) -> Tuple[str, str, Optional[int], Optional[int]]:
    """
    Extracts PDU type, Advertiser MAC address (AdvA), RSSI (dBm), and RF Channel from an nRF Sniffer packet.
    Follows Bluetooth Core Specification Vol 6 Part B §2.3.4 (Extended Advertising PDU) and §2.3.1 (Legacy PDU).
    Properly parses both primary channels (ADV_EXT_IND) and secondary channels (AUX_ADV_IND), including LE Coded PHY.
    """
    mac_address = "UNKNOWN"
    pdu_type_str = "UNKNOWN_OR_DATA"

    aa_idx, pdu_offset, rf_channel, rssi_dbm = locate_ble_packet(data)

    if pdu_offset != -1 and len(data) >= pdu_offset + 2:
        pdu_type = data[pdu_offset] & 0x0F
        pdu_len = data[pdu_offset + 1]
        payload = data[pdu_offset + 2 : pdu_offset + 2 + pdu_len] if len(data) >= pdu_offset + 2 + pdu_len else data[pdu_offset + 2 :]

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
            pdu_type_str = PDU_TYPE_MAP.get(pdu_type, f"PDU_{pdu_type:02X}")
            # Legacy PDU types: ADV_IND(0), ADV_DIRECT_IND(1), ADV_NONCONN_IND(2), SCAN_RSP(4), ADV_SCAN_IND(6)
            if pdu_type in (0x00, 0x01, 0x02, 0x04, 0x06):
                if len(payload) >= 6:
                    mac_bytes = payload[0:6]
                    mac_address = ":".join(f"{b:02X}" for b in reversed(mac_bytes))

    # Safety fallback: If mac_address is still UNKNOWN but ASTM Remote ID marker is present in packet,
    # locate AdvA preceding the AD structure in extended advertising packets
    if mac_address == "UNKNOWN":
        marker_16 = b"\x16\xfa\xff\x0d"
        idx = data.find(marker_16)
        if idx >= 9:
            for cand_mac_start in (idx - 9, idx - 7):
                if cand_mac_start >= 0 and len(data) >= cand_mac_start + 6:
                    cand_mac = data[cand_mac_start : cand_mac_start + 6]
                    if cand_mac != b"\x00" * 6 and cand_mac != b"\xff" * 6:
                        flags_byte = data[cand_mac_start - 1] if cand_mac_start >= 1 else 0
                        if flags_byte & 0x01:
                            mac_address = ":".join(f"{b:02X}" for b in reversed(cand_mac))
                            pdu_type_str = "ADV_EXT_IND/AUX_ADV_IND"
                            break

    return pdu_type_str, mac_address, rssi_dbm, rf_channel


def extract_remote_id_info(data: bytes, pdu_type_str: str) -> Optional[Dict[str, Any]]:
    """
    Extracts ASTM F3411 Remote ID information from raw packet bytes.
    Extracts the Advertising Data (AdvData) structure from both legacy and extended (AUX_ADV_IND)
    PDUs, with a robust fallback to direct LTV marker scanning.
    """
    adv_data = None
    aa_idx, pdu_offset, rf_channel, _ = locate_ble_packet(data)

    if pdu_offset != -1 and len(data) >= pdu_offset + 2:
        pdu_type = data[pdu_offset] & 0x0F
        pdu_len = data[pdu_offset + 1]
        payload = data[pdu_offset + 2 : pdu_offset + 2 + pdu_len] if len(data) >= pdu_offset + 2 + pdu_len else data[pdu_offset + 2 :]

        if pdu_type == 0x07:
            if len(payload) >= 1:
                ext_hdr_len = payload[0] & 0x3F
                if len(payload) >= 1 + ext_hdr_len:
                    adv_data = payload[1 + ext_hdr_len :]
        elif pdu_type in (0x00, 0x01, 0x02, 0x04, 0x06):
            if len(payload) >= 6:
                adv_data = payload[6:]

    rid_result = None
    if adv_data and len(adv_data) >= 29:
        rid_result = extract_ble_rid_payload(adv_data)

    # Robust fallback: if adv_data was not cleanly sliced or did not parse,
    # locate AD Type 0x16 + UUID 0xFFFA + AppCode 0x0D directly in data
    if not rid_result:
        marker_16 = b"\x16\xfa\xff\x0d"
        idx = data.find(marker_16)
        if idx != -1 and idx >= 1:
            ad_len = data[idx - 1]
            if len(data) >= idx + ad_len:
                candidate_adv = data[idx - 1 : idx + ad_len]
                rid_result = extract_ble_rid_payload(candidate_adv)
            if not rid_result and len(data) >= idx + 28:
                counter = data[idx + 4]
                astm_slice = data[idx + 5 :]
                parsed_messages, msgs_b64 = parse_astm_payload(astm_slice)
                if parsed_messages:
                    rid_result = (counter, astm_slice, parsed_messages, msgs_b64)

    if not rid_result:
        return None

    counter, astm_data, parsed_messages, messages_b64 = rid_result

    # Distinguish BLE 4 Legacy vs BLE 5 Extended Advertising
    msg_type = (astm_data[0] >> 4) if len(astm_data) > 0 else None
    if (
        msg_type == 0xF
        or len(astm_data) > 30
        or pdu_type_str in ("ADV_EXT_IND", "AUX_ADV_IND", "ADV_EXT_IND/AUX_ADV_IND", "PDU_07")
        or pdu_type_str.startswith("ADV_EXT")
        or pdu_type_str.startswith("AUX_")
    ):
        transport = "ble5_extended"
    else:
        transport = "ble4_legacy"

    return {
        "transport": transport,
        "counter": counter,
        "parsed_messages": parsed_messages,
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
    group_by_mac: bool = False,
    active_ble_mode: Optional[str] = None,
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
        is_bt5_pdu = (pdu_type_str in ("ADV_EXT_IND", "AUX_ADV_IND", "ADV_EXT_IND/AUX_ADV_IND", "PDU_07") or pdu_type_str.startswith("ADV_EXT") or pdu_type_str.startswith("AUX_"))
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
        "remote_id": remote_id_info,
        "active_ble_mode": active_ble_mode
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
    ble_mode: str = "hop",
    bt5_dwell_s: float = 5.0,
    bt4_dwell_s: float = 1.0,
    group_by_mac: bool = False,
    stats_format: str = "table",
    stats_interval: float = 2.0,
    raw_pcap_port: Optional[int] = None
):
    global nrf_proc, hopper_controller, fifo_created_path

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

        hopper_controller = BleModeHopperController(
            nrf_port=nrf_port,
            pcap_path=pcap_path,
            mode=ble_mode,
            bt5_dwell_s=bt5_dwell_s,
            bt4_dwell_s=bt4_dwell_s,
            filter_mac=filter_mac,
        )
        if ble_mode == "hop":
            sys.stderr.write(f"[*] Starting BLE Hopper Controller on {nrf_port} (Mode: hop, BT5: {bt5_dwell_s}s, BT4: {bt4_dwell_s}s)...\n")
        else:
            sys.stderr.write(f"[*] Starting BLE Sniffer on {nrf_port} (Mode: {ble_mode})...\n")
        hopper_controller.start()
        time.sleep(0.3)
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

    raw_pcap_sock: Optional[socket.socket] = None
    if raw_pcap_port:
        try:
            raw_pcap_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_pcap_sock.connect(("127.0.0.1", raw_pcap_port))
            sys.stderr.write(f"[*] Connected to local raw BLE PCAP tap on 127.0.0.1:{raw_pcap_port}\n")
        except Exception as e:
            sys.stderr.write(f"[-] Could not connect to raw PCAP tap port {raw_pcap_port}: {e}\n")
            raw_pcap_sock = None

    f = None
    try:
        last_display_time = 0.0
        while True:
            # Check controller health if live
            if hopper_controller and not hopper_controller.running:
                break

            if not os.path.exists(pcap_path):
                time.sleep(0.1)
                continue

            try:
                f = open(pcap_path, "rb")
            except Exception:
                time.sleep(0.05)
                continue

            # Read 24-byte Global PCAP Header
            hdr = f.read(24)
            if len(hdr) < 24:
                f.close()
                time.sleep(0.05)
                continue

            magic, major, minor, tz, sig, snaplen, network = struct.unpack("<IHHiIII", hdr)
            endian = ">" if magic in (0xd4c3b2a1, 0x4d3cb2a1) else "<"

            # Process packets for this session/hop
            while True:
                pkthdr = f.read(16)
                if not pkthdr or len(pkthdr) < 16:
                    # Pipe EOF or switch in progress
                    if group_by_mac and sys.stdout.isatty() and time.time() - last_display_time >= stats_interval and mac_stats:
                        display_mac_stats(stats_format=stats_format, pretty=pretty, clear_screen=True, stream=sys.stdout, is_final=False)
                        last_display_time = time.time()
                    
                    if not nrf_port:
                        # Static PCAP file finished
                        break

                    # Check if controller is still alive
                    if hopper_controller and not hopper_controller.running:
                        break
                    
                    # FIFO closed by sub-process switch; break inner loop to reopen on next PCAP stream
                    break

                ts_sec, ts_usec, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkthdr)
                if incl_len > 65535:
                    continue

                data = f.read(incl_len)
                while len(data) < incl_len:
                    if hopper_controller and not hopper_controller.running:
                        break
                    time.sleep(0.002)
                    more = f.read(incl_len - len(data))
                    if more:
                        data += more
                    else:
                        time.sleep(0.005)
                if len(data) < incl_len:
                    break

                now_ts = time.time()
                if nrf_port:
                    # Live capture via nRF dongle: always use host physical arrival time
                    # (nRF dongle hardware counter ticks are not real-world UTC epochs)
                    ts = now_ts
                else:
                    # Static PCAP replay: use PCAP ts if valid epoch, otherwise fall back to host arrival time
                    ts = ts_sec + (ts_usec / 1e6)
                    if not is_valid_timestamp(ts, ref_now=now_ts, max_skew_s=86400.0):
                        ts = now_ts

                active_mode = hopper_controller.current_mode if hopper_controller else None

                # Forward raw BLE packet (DLT 272) to binary PCAP streamer tap before filtering
                if raw_pcap_sock:
                    try:
                        rec_hdr = build_pcap_record_header(ts, len(data))
                        raw_pcap_sock.sendall(rec_hdr + data)
                    except Exception:
                        try:
                            raw_pcap_sock.close()
                            raw_pcap_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            raw_pcap_sock.connect(("127.0.0.1", raw_pcap_port))
                            rec_hdr = build_pcap_record_header(ts, len(data))
                            raw_pcap_sock.sendall(rec_hdr + data)
                        except Exception:
                            pass

                process_packet(
                    data, ts,
                    pretty=pretty,
                    only_rid=only_rid,
                    only_bt5=only_bt5,
                    filter_mac=filter_mac,
                    filter_mac_bytes_le=filter_mac_bytes_le,
                    filter_mac_bytes_be=filter_mac_bytes_be,
                    group_by_mac=group_by_mac,
                    active_ble_mode=active_mode
                )
                if group_by_mac and sys.stdout.isatty() and time.time() - last_display_time >= stats_interval and mac_stats:
                    display_mac_stats(stats_format=stats_format, pretty=pretty, clear_screen=True, stream=sys.stdout, is_final=False)
                    last_display_time = time.time()

            if f:
                f.close()
                f = None

            if not nrf_port:
                # Finished static PCAP file
                break

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
        help="Only output Bluetooth 5 Extended Advertising packets"
    )
    parser.add_argument(
        "--ble-mode",
        choices=["hop", "extended", "legacy", "all"],
        default="hop",
        help="BLE sniffer operational mode: 'hop' (cycles BT5/BT4), 'extended' (BT5 only), 'legacy' (BT4 only), 'all' (1M uncoded)"
    )
    parser.add_argument(
        "--bt5-dwell",
        type=float,
        default=5.0,
        help="Dwell time in seconds on BT5 Extended / Coded mode when hopping"
    )
    parser.add_argument(
        "--bt4-dwell",
        type=float,
        default=1.0,
        help="Dwell time in seconds on BT4 Legacy mode when hopping"
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
    parser.add_argument(
        "--raw-pcap-port",
        type=int,
        default=None,
        help="Optional local TCP port on 127.0.0.1 to stream raw unfiltered BLE PCAP records"
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

    if args.ble_mode in ("extended", "bt5"):
        args.only_bt5 = True
    effective_mode = "extended" if args.only_bt5 else args.ble_mode

    run_sniffer(
        pcap_path=args.rx_pcap,
        nrf_port=args.nrf_port,
        pretty=args.pretty,
        only_rid=args.only_rid,
        only_bt5=args.only_bt5,
        filter_mac=args.filter_mac,
        ble_mode=effective_mode,
        bt5_dwell_s=args.bt5_dwell,
        bt4_dwell_s=args.bt4_dwell,
        group_by_mac=args.group_by_mac,
        stats_format=args.stats_format,
        stats_interval=args.stats_interval,
        raw_pcap_port=args.raw_pcap_port
    )


if __name__ == "__main__":
    main()
