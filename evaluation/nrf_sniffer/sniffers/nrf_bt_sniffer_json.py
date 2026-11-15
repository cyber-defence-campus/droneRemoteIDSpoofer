#!/usr/bin/env python3
"""
OTA Bluetooth Sniffer on the nRF Sniffer for Bluetooth LE firmware with Real-Time JSON Output.
Captures Bluetooth packets over the air (the firmware driven directly over its serial port, see
nrf_uart), decodes ASTM F3411 Drone Remote ID broadcasts when present, and streams structured
JSON data to stdout. Replays Nordic BLE PCAP files the same way (--rx-pcap).
Supports filtering by MAC address, Remote ID telemetry, and Bluetooth 5 Extended Advertising.
"""

import argparse
import json
import os
import signal
import socket
import struct
import sys
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


from ..parser import extract_ble_rid_payload
from .nordic_ble import ADV_EXT_IND, PHY_1M, PHY_2M, PHY_CODED, NordicBleFrame, parse_frame
from .nordic_clock import DongleClock, firmware_time_us
from .nrf_device import find_sniffer_ports
from .nrf_uart import NordicSnifferError, UartHopper
from ..timestamp_utils import format_iso_timestamp

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

# Where a record's "timestamp" comes from (JSON field timestamp_source)
TS_SOURCE_DONGLE = "dongle_clock"
# Dongle clock in the first seconds of a run, before a promptly delivered frame fixed the offset
TS_SOURCE_DONGLE_UNSETTLED = "dongle_clock_unsettled"
TS_SOURCE_HOST_ARRIVAL = "host_arrival"
TS_SOURCE_NRF_PCAP = "nrf_pcap"

# First 4 bytes of a PCAP file header (byte orders, microsecond and nanosecond variants)
PCAP_MAGICS = (b"\xa1\xb2\xc3\xd4", b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\x3c\x4d", b"\x4d\x3c\xb2\xa1")
NORDIC_PROTOCOL_VERSION = 3


def is_nordic_packet(data: bytes) -> bool:
    """
    True if data is one Nordic BLE (DLT 272) frame of the protocol version nrfutil's sniffer
    writes: board(1), payload length (16-bit LE), protocol version, packet counter (2), packet id,
    then the payload. A frame may be shorter than its declared length (a truncated capture, kept
    as received), never longer; anything else is a framing error and must not be passed on.
    """
    return (len(data) >= 7 and data[3] == NORDIC_PROTOCOL_VERSION
            and len(data) <= 7 + int.from_bytes(data[1:3], "little"))
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
    global out_file_handle, summary_printed, mac_stats, group_by_mac_enabled, stats_format_choice, pretty_json_choice
    if not summary_printed and mac_stats:
        summary_printed = True
        out_stream = sys.stdout if group_by_mac_enabled else sys.stderr
        display_mac_stats(stats_format=stats_format_choice, pretty=pretty_json_choice, clear_screen=False, stream=out_stream, is_final=True)

    if out_file_handle:
        out_file_handle.close()
        out_file_handle = None

    sys.stderr.write("[*] Capture stopped.\n")
    sys.exit(0)


def _frame_pdu_type(frame: NordicBleFrame) -> str:
    return PDU_TYPE_MAP.get(frame.pdu_type, f"PDU_{frame.pdu_type:02X}")


def extract_crc_ok(data: bytes) -> Optional[bool]:
    """
    The link-layer CRC status the nRF Sniffer firmware reports for a Nordic BLE (DLT 272) frame
    (bit 0 of the packet flags: the BLE CRC-24 check passed), or None if it is not one.
    """
    frame = parse_frame(data)
    return frame.crc_ok if frame else None


def extract_phy(data: bytes) -> Optional[str]:
    """
    The PHY the nRF Sniffer firmware received a Nordic BLE (DLT 272) frame on: "1M", "2M",
    "Coded S=8" or "Coded S=2" (packet flags bits 4-6 and, on Coded PHY, the Coding Indicator).
    "Coded" if the Coding Indicator is invalid (corrupted frame), None if it is not a frame or the
    PHY value is unknown.
    """
    frame = parse_frame(data)
    if frame is None:
        return None
    if frame.phy == PHY_CODED:
        return {0: "Coded S=8", 1: "Coded S=2"}.get(frame.coding_indicator, "Coded")
    return {PHY_1M: "1M", PHY_2M: "2M"}.get(frame.phy)


def parse_packet_metadata(data: bytes) -> Tuple[str, str, Optional[int], Optional[int]]:
    """
    PDU type, advertiser address (AdvA, "UNKNOWN" if the PDU carries none), RSSI (dBm) and RF
    channel of a Nordic BLE (DLT 272) frame, parsed by its structure (see nordic_ble). Covers
    legacy PDUs and extended ones (ADV_EXT_IND / AUX_ADV_IND) on every PHY.
    """
    frame = parse_frame(data)
    if frame is None:
        return "UNKNOWN_OR_DATA", "UNKNOWN", None, None
    adva = frame.advertiser_address
    mac = ":".join(f"{b:02X}" for b in reversed(adva)) if adva else "UNKNOWN"
    channel = frame.channel if frame.channel <= 39 else None
    return _frame_pdu_type(frame), mac, frame.rssi_dbm, channel


# RF-channel filter state for BT5: the latest AuxPtr seen per advertising set (ADI), used to
# accept secondary-channel packets whose pointer arrived on a filtered primary channel.
# ADI -> {"origin_ok": bool, "primary_channel": int, "aux_channel": int, "ts": float}
AUX_PTR_MATCH_WINDOW_S = 0.5
last_aux_ptr: Dict[Optional[int], Dict[str, Any]] = {}


def _ext_adi_auxptr(frame: NordicBleFrame) -> Tuple[Optional[int], Optional[int]]:
    """(ADI, AuxPtr channel index) from an extended advertising PDU's header; either may be None."""
    header = frame.extended_header
    if not header:
        return None, None
    flags = header[0]
    idx = 1
    if flags & 0x01:  # AdvA
        idx += 6
    if flags & 0x02:  # TargetA
        idx += 6
    if flags & 0x04:  # CTEInfo
        idx += 1
    adi = None
    if flags & 0x08:  # ADI
        if len(header) < idx + 2:
            return None, None
        adi = header[idx] | (header[idx + 1] << 8)
        idx += 2
    aux_channel = None
    if flags & 0x10 and len(header) >= idx + 3:  # AuxPtr
        aux_channel = header[idx] & 0x3F
    return adi, aux_channel


def channel_filter_accepts(data: bytes, rf_channel: Optional[int], ts: float,
                           filter_channels: List[int]) -> Tuple[bool, Optional[int]]:
    """
    Whether a packet passes the RF-channel filter. Returns (accepted, primary_channel). Packets on
    a filtered channel always pass; a BT5 secondary-channel packet (AUX_ADV_IND / AUX_CHAIN_IND)
    also passes when the latest AuxPtr for its advertising set (ADI) was received on a filtered
    primary channel and pointed to this packet's channel. Every AuxPtr is tracked (even from
    rejected packets) so a stale pointer cannot be matched by a later aux packet.
    """
    frame = parse_frame(data)
    adi, aux_channel = _ext_adi_auxptr(frame) if frame is not None else (None, None)

    accepted = rf_channel in filter_channels
    primary_channel = rf_channel if rf_channel is not None and rf_channel >= 37 else None

    if not accepted and aux_channel is not None and rf_channel is not None and rf_channel < 37:
        ptr = last_aux_ptr.get(adi)
        if (ptr and ptr["origin_ok"] and ptr["aux_channel"] == rf_channel
                and 0 <= ts - ptr["ts"] <= AUX_PTR_MATCH_WINDOW_S):
            accepted = True
            primary_channel = ptr["primary_channel"]

    if aux_channel is not None:
        if rf_channel is not None and rf_channel >= 37:
            primary_channel = rf_channel
        last_aux_ptr[adi] = {
            "origin_ok": accepted,
            "primary_channel": primary_channel,
            "aux_channel": aux_channel,
            "ts": ts,
        }

    return accepted, primary_channel


def extract_remote_id_info(data: bytes, pdu_type_str: str) -> Optional[Dict[str, Any]]:
    """
    ASTM F3411 Remote ID of a Nordic BLE (DLT 272) frame: transport (ble4_legacy for a legacy
    advertising PDU, ble5_extended for an extended one), message counter and decoded messages,
    from the PDU's advertising data. In a frame that failed its CRC, a Remote ID structure with a
    length byte other than ASTM prescribes is read with the prescribed length (see
    extract_ble_rid_payload). None if the frame carries no Remote ID.
    """
    frame = parse_frame(data)
    if frame is None:
        return None
    rid_result = extract_ble_rid_payload(frame.advertising_data, repair_lengths=not frame.crc_ok)
    if not rid_result:
        return None
    counter, _, parsed_messages, _ = rid_result
    return {
        "transport": "ble5_extended" if frame.pdu_type == ADV_EXT_IND else "ble4_legacy",
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
    group_by_mac: bool = False,
    active_ble_mode: Optional[str] = None,
    timestamp_source: Optional[str] = None,
    filter_channels: Optional[List[int]] = None,
):
    """
    Processes raw link-layer bytes, decodes any present Remote ID ASTM payloads,
    filters by MAC address, RF channel, BT5 extended advertising, or Remote ID if specified,
    and streams as a formatted JSON object.
    """
    if not data:
        return

    pdu_type_str, mac_address, rssi_dbm, rf_channel = parse_packet_metadata(data)

    # RF-channel restriction (ADI-aware: keeps BT5 aux packets whose pointer was on a kept channel)
    if filter_channels is not None:
        accepted, _ = channel_filter_accepts(data, rf_channel, ts, filter_channels)
        if not accepted:
            return

    if filter_mac and mac_address.upper() != filter_mac:
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
        "timestamp_iso": format_iso_timestamp(ts),
        "pdu_type": pdu_type_str,
        "mac": mac_address,
        "rf_channel": rf_channel,
        "rssi_dbm": rssi_dbm,
        "crc_ok": extract_crc_ok(data),
        "phy": extract_phy(data),
        "raw_length": len(data),
        "raw_hex": data.hex().upper(),
        "remote_id": remote_id_info,
        "active_ble_mode": active_ble_mode,
        "timestamp_source": timestamp_source,
    }

    if not group_by_mac:
        # Print JSON record directly to stdout in per-packet stream mode
        json_str = json.dumps(record, indent=2 if pretty else None, default=str)
        print(json_str)
        sys.stdout.flush()

    if out_file_handle:
        out_file_handle.write(json.dumps(record, default=str) + "\n")
        out_file_handle.flush()


def iter_pcap_file(path: str):
    """Yields (record time, frame) of a classic PCAP file of either byte order."""
    with open(path, "rb") as f:
        hdr = f.read(24)
        if len(hdr) < 24 or hdr[:4] not in PCAP_MAGICS:
            raise ValueError(f"{path} is not a PCAP file")
        endian = ">" if hdr[:4] in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d") else "<"
        while True:
            pkthdr = f.read(16)
            if len(pkthdr) < 16:
                return
            ts_sec, ts_usec, incl_len, _ = struct.unpack(f"{endian}IIII", pkthdr)
            if incl_len > 65535:
                sys.stderr.write(f"[!] Implausible record length {incl_len} in {path}; stopping there\n")
                return
            data = f.read(incl_len)
            if len(data) < incl_len:
                return
            yield ts_sec + ts_usec / 1e6, data


def run_sniffer(
    pcap_path: Optional[str] = None,
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
    raw_pcap_port: Optional[int] = None,
    filter_channels: Optional[List[int]] = None,
):
    """
    Live capture from the sniffer on nrf_port (scanning in ble_mode, switching BT5/BT4 in hop
    mode), or replay of the Nordic BLE PCAP file pcap_path. Every frame goes to the raw PCAP tap
    (raw_pcap_port) and is decoded to a JSON record.
    """
    if filter_mac:
        filter_mac = filter_mac.replace("-", ":").upper()

    if nrf_port:
        if not os.path.exists(nrf_port):
            # Only another nRF sniffer (by USB vendor) may replace it, never an arbitrary serial device
            alt_ports = find_sniffer_ports()
            if not alt_ports:
                sys.stderr.write(f"[-] Error: Specified port {nrf_port} not found and no nRF sniffer is connected.\n")
                sys.exit(1)
            sys.stderr.write(f"[!] Warning: Specified port {nrf_port} not found! Using the nRF sniffer on {alt_ports[0]}\n")
            nrf_port = alt_ports[0]
        if ble_mode == "hop":
            sys.stderr.write(f"[*] Starting BLE sniffer on {nrf_port} (Mode: hop, BT5: {bt5_dwell_s}s, BT4: {bt4_dwell_s}s)...\n")
        else:
            sys.stderr.write(f"[*] Starting BLE sniffer on {nrf_port} (Mode: {ble_mode})...\n")
    else:
        sys.stderr.write(f"[*] Reading BLE PCAP file {pcap_path}...\n")

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

    last_display_time = 0.0
    malformed_records = 0
    pcap_tap_lost = False

    def handle(data: bytes, ts: float, ts_source: str, active_mode: Optional[str]) -> None:
        nonlocal raw_pcap_sock, last_display_time, pcap_tap_lost
        # Forward raw BLE packet (DLT 272) to binary PCAP streamer tap before filtering
        if raw_pcap_sock:
            try:
                raw_pcap_sock.sendall(build_pcap_record_header(ts, len(data)) + data)
            except OSError:
                try:
                    raw_pcap_sock.close()
                    raw_pcap_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    raw_pcap_sock.connect(("127.0.0.1", raw_pcap_port))
                    raw_pcap_sock.sendall(build_pcap_record_header(ts, len(data)) + data)
                except OSError as e:
                    if not pcap_tap_lost:
                        sys.stderr.write(f"[-] Lost the raw BLE PCAP tap on port {raw_pcap_port}; "
                                         f"BLE frames are missing from the PCAPs until it is back: {e}\n")
                    pcap_tap_lost = True
                else:
                    if pcap_tap_lost:
                        sys.stderr.write(f"[*] Reconnected to the raw BLE PCAP tap on port {raw_pcap_port}\n")
                    pcap_tap_lost = False
        process_packet(
            data, ts,
            pretty=pretty,
            only_rid=only_rid,
            only_bt5=only_bt5,
            filter_mac=filter_mac,
            group_by_mac=group_by_mac,
            active_ble_mode=active_mode,
            timestamp_source=ts_source,
            filter_channels=filter_channels,
        )
        if group_by_mac and sys.stdout.isatty() and time.time() - last_display_time >= stats_interval and mac_stats:
            display_mac_stats(stats_format=stats_format, pretty=pretty, clear_screen=True, stream=sys.stdout, is_final=False)
            last_display_time = time.time()

    try:
        if nrf_port:
            # Reception times from the dongle's clock, synced by the hopper's timestamp requests
            dongle_clock = DongleClock()
            # Pin the firmware's primary hop sequence when the filter is a subset of 37/38/39,
            # so the radio dwells only on kept primaries (and follows their aux chains) instead of
            # hopping all three and discarding two thirds. Mixed/secondary filters fall back to
            # host-side accounting via channel_filter_accepts.
            adv_hop = None
            if filter_channels:
                primaries = [c for c in filter_channels if c in (37, 38, 39)]
                if primaries and len(primaries) == len(filter_channels):
                    adv_hop = primaries
            hopper = UartHopper(nrf_port, ble_mode, bt5_dwell_s, bt4_dwell_s, clock=dongle_clock, adv_hop=adv_hop)
            announced = False
            for data, mode in hopper.frames():
                if not announced:
                    sys.stderr.write(f"[*] nRF sniffer firmware {hopper.firmware_version} on {nrf_port}\n")
                    if hopper.dropped_before_start:
                        sys.stderr.write(f"[*] Dropped {hopper.dropped_before_start} frame(s) the dongle had queued "
                                         f"before this run (their reception time cannot be told)\n")
                    announced = True
                if not is_nordic_packet(data):
                    malformed_records += 1
                    if malformed_records == 1 or malformed_records % 100 == 0:
                        sys.stderr.write(f"[!] Skipped {malformed_records} frame(s) that are not one Nordic BLE frame\n")
                    continue
                raw_us = firmware_time_us(data)
                if raw_us is not None:
                    ts, settled = dongle_clock.reception_time(raw_us)
                    ts_source = TS_SOURCE_DONGLE if settled else TS_SOURCE_DONGLE_UNSETTLED
                else:
                    ts, ts_source = time.time(), TS_SOURCE_HOST_ARRIVAL
                handle(data, ts, ts_source, mode)
        else:
            # Replay: the recorded PCAP time as-is (implausible values are flagged downstream)
            for ts, data in iter_pcap_file(pcap_path):
                handle(data, ts, TS_SOURCE_NRF_PCAP, None)
    except KeyboardInterrupt:
        pass
    except NordicSnifferError as e:
        sys.stderr.write(f"[-] nRF sniffer: {e}\n")
    except Exception as e:
        sys.stderr.write(f"[-] Uncaught exception during capture: {e}\n")
    finally:
        cleanup()


def main():
    parser = argparse.ArgumentParser(
        description="OTA Bluetooth Sniffer using nRF Sniffer with Real-Time JSON Output",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        "-p", "--nrf-port",
        help="Serial port of the nRF sniffer dongle (e.g. /dev/ttyACM0) for live capture"
    )
    parser.add_argument(
        "-f", "--rx-pcap",
        help="Replay a Nordic BLE PCAP file instead of capturing live"
    )
    parser.add_argument(
        "-m", "--filter-mac",
        help="Filter captured packets by advertiser MAC address (case-insensitive, e.g. 02:ee:c0:00:00:08)"
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
        choices=["hop", "extended", "ble5", "legacy", "ble4"],
        default="hop",
        help="BLE sniffer operational mode: 'hop' (cycles BT5/BT4), 'extended'/'ble5' (BT5 Coded only), "
             "'legacy'/'ble4' (BT4 only)"
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
    parser.add_argument(
        "-c", "--filter-channel",
        dest="filter_channels",
        type=int,
        nargs="+",
        choices=range(0, 40),
        metavar="CH",
        default=None,
        help="Only keep packets on these BLE RF channels (e.g. 37). A subset of 37/38/39 also "
             "pins the firmware's primary hop sequence; BT5 aux packets whose pointer arrived on "
             "a kept channel are kept too."
    )

    args = parser.parse_args()
    if not args.nrf_port and not args.rx_pcap:
        parser.error("give --nrf-port for live capture or --rx-pcap to replay a PCAP file")

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

    if args.ble_mode in ("extended", "ble5"):
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
        raw_pcap_port=args.raw_pcap_port,
        filter_channels=args.filter_channels,
    )


if __name__ == "__main__":
    main()
