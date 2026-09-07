#!/usr/bin/env python3
import argparse
import json
import logging
import os
import subprocess
import sys
import threading
import time
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any

# Add parent directory to path to import drone_rid_spoofer
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import sniff
import scapy.layers.dot11 as dot11

from drone_rid_spoofer.spoofer import DroneSpoofer
from drone_rid_spoofer.transport.wifi import WifiBackend
from drone_rid_spoofer.helpers import get_random_serial_number, random_location
from drone_rid_spoofer.messages import MsgType

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)


def get_msg_type_name(m_type: int) -> str:
    names = {
        0x00: "Basic ID",
        0x01: "Location",
        0x02: "Auth",
        0x03: "Self ID",
        0x04: "System",
        0x05: "Operator ID",
        0x0F: "Message Pack"
    }
    return names.get(m_type, f"Type_0x{m_type:02X}")


class SnifferThread(threading.Thread):
    def __init__(self, iface: str, duration: float, label: str):
        super().__init__()
        self.iface = iface
        self.duration = duration
        self.label = label
        self.running = False
        self.packets_received: Dict[str, List[float]] = {}
        self.raw_records: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        
    def run(self):
        self.running = True
        logger.info(f"Starting {self.label} sniffer on {self.iface} for up to {self.duration} seconds...")
        import socket, struct, select
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            sock.bind((self.iface, 0))
            
            while self.running:
                ready = select.select([sock], [], [], 0.05)
                if not ready[0]:
                    continue
                    
                frame = sock.recv(4096)
                if len(frame) < 24:
                    continue
                    
                # Fast check for OUI
                oui_idx = frame.find(b'\xfa\x0b\xbc')
                if oui_idx == -1 or oui_idx < 2 or frame[oui_idx - 2] != 0xdd:
                    continue
                    
                radiotap_len = struct.unpack('<H', frame[2:4])[0]
                if len(frame) < radiotap_len + 24:
                    continue
                    
                fc = frame[radiotap_len]
                if fc != 0x80:  # Not a beacon
                    continue
                    
                mac_bytes = frame[radiotap_len + 10 : radiotap_len + 16]
                mac = ':'.join(f'{b:02x}' for b in mac_bytes).upper()
                ts = time.time()
                raw_length = len(frame)
                
                parsed_messages = []
                ie_len = frame[oui_idx - 1]
                if oui_idx + 3 + ie_len - 3 <= len(frame):
                    payload_bytes = frame[oui_idx + 3 : oui_idx + 3 + ie_len - 3]
                else:
                    continue
                
                if len(payload_bytes) >= 5 and payload_bytes[0] == 0x0D:
                    msg_type_header = (payload_bytes[2] >> 4) & 0x0F
                    msg_size = payload_bytes[3]
                    num_msgs = payload_bytes[4]
                    
                    if msg_type_header == 0x0F and msg_size == 25:
                        offset = 5
                        for _ in range(num_msgs):
                            if offset + 25 <= len(payload_bytes):
                                msg_chunk = payload_bytes[offset:offset + 25]
                                m_type = (msg_chunk[0] >> 4) & 0x0F
                                m_name = get_msg_type_name(m_type)
                                msg_dict = {"type": m_name, "raw_hex": msg_chunk.hex().upper()}
                                if m_type == 0x00:  # Basic ID
                                    id_str = msg_chunk[2:22].decode('ascii', errors='ignore').rstrip('\x00')
                                    msg_dict["id"] = id_str
                                parsed_messages.append(msg_dict)
                                offset += 25
                                
                record = {
                    "timestamp": ts,
                    "mac": mac,
                    "raw_length": raw_length,
                    "parsed_messages": parsed_messages
                }

                with self.lock:
                    if mac not in self.packets_received:
                        self.packets_received[mac] = []
                    self.packets_received[mac].append(ts)
                    self.raw_records.append(record)
                    
        except Exception as e:
            logger.error(f"Error running sniffer on {self.iface}: {e}")
        finally:
            self.running = False
            if 'sock' in locals():
                sock.close()
        logger.info(f"{self.label} sniffer stopped.")


def instrument_backend(backend: WifiBackend, active_macs: Optional[List[str]] = None, max_cycles: Optional[int] = None):
    """Monkey-patch Wi-Fi backend to record transmit timestamps, ASTM messages, and cycle indexing."""
    if active_macs is None:
        active_macs = []
    backend.inject_times = []
    backend.build_times = []
    backend.loop_times = []
    backend.missed_deadlines = 0
    backend.packets_transmitted: Dict[str, List[float]] = {mac.upper(): [] for mac in active_macs}
    backend.expected_records: List[Tuple[int, float, str, str]] = []
    backend.tx_records: List[Tuple[int, float, str, str]] = []
    backend.lock = threading.Lock()
    backend.current_cycle = 0
    backend.max_cycles = max_cycles
    backend.registered_drones = {}

    orig_start = getattr(backend, 'start', None)
    if orig_start and callable(orig_start):
        def patched_start(drones, packet_builder, *a, **kw):
            for drone in drones:
                if getattr(drone, 'mac_address', None):
                    mac_upper = drone.mac_address.upper()
                    serial_str = drone.serial.decode('utf-8', errors='replace') if isinstance(drone.serial, bytes) else str(drone.serial)
                    backend.registered_drones[mac_upper] = serial_str
                    if mac_upper not in backend.packets_transmitted:
                        backend.packets_transmitted[mac_upper] = []
            return orig_start(drones, packet_builder, *a, **kw)
        backend.start = patched_start

    def patched_transmit_loop():
        while backend._running and not backend._drones:
            time.sleep(0.01)

        dest_bytes = bytes.fromhex(backend.DEST_ADDR.replace(':', ''))
        
        is_5ghz = backend.channel >= 36
        if is_5ghz:
            supp_rates = b'\x8c\x12\x98\x24'  # 6, 9, 12, 18 Mbps (6, 12 basic)
            ext_rates = b'\x30\x48\x60\x6c'   # 24, 36, 48, 54 Mbps
            effective_rate = 6.0 if backend.rate_mbps <= 1.0 else backend.rate_mbps
        else:
            supp_rates = backend.SUPPORTED_RATES
            ext_rates = backend.EXTENDED_SUPPORTED_RATES
            effective_rate = backend.rate_mbps

        # Pre-compile static IEs that never change across drones
        ie_rates = dot11.Dot11Elt(ID='Rates', info=supp_rates)
        ie_dsset = dot11.Dot11Elt(ID='DSset', info=bytes([backend.channel & 0xFF]))
        ie_tim = dot11.Dot11Elt(ID='TIM', info=b'\x00\x01\x00\x00')
        ie_erp = dot11.Dot11Elt(ID='ERPinfo', info=b'\x00')
        ie_esr = dot11.Dot11Elt(ID='ESRates', info=ext_rates)
        static_ies_bytes = bytes(ie_rates / ie_dsset / ie_tim / ie_erp / ie_esr)
        
        radiotap_bytes = bytes(dot11.RadioTap(present='Rate', Rate=effective_rate))

        next_tick = time.time()
        while backend._running:
            t_loop_start = time.monotonic()
            packets = []
            current_tsf = int(time.time() * 1000000) % (2**64)
            cycle_idx = getattr(backend, 'current_cycle', 0)
            
            # Beacon Base (Timestamp & Cap) is identical for all drones in the same batch
            beacon_base_bytes = bytes(dot11.Dot11Beacon(cap='ESS' if backend.ess else 0, timestamp=current_tsf))

            t_build_start = time.monotonic()
            for drone in backend._drones:
                if not getattr(drone, 'active', True):
                    continue

                serial = drone.serial
                mac_addr = drone.mac_address.upper()

                # Build ASTM messages from current drone state
                messages = backend._packet_builder(drone)

                with backend.lock:
                    backend.expected_records.append((cycle_idx, time.time(), mac_addr, "Message Pack"))

                seq_num = backend._seq_nums.get(serial, 0)
                backend._seq_nums[serial] = (seq_num + 1) % 4096

                msg_count_val = backend._msg_counters.get(serial, 0)
                backend._msg_counters[serial] = (msg_count_val + 1) & 0xFF

                msg_count_bytes = bytes([len(messages) & 0xFF])
                header = bytes([backend.APP_CODE, msg_count_val]) + backend.pack_header_prefix + msg_count_bytes
                vendor_data = header + b''.join(messages)

                serial_str = serial.decode('ascii', errors='replace') if isinstance(serial, bytes) else str(serial)
                ssid = (backend.SSID_PREFIX + serial_str)[: backend.SSID_MAX_LEN]
                
                # 1. Dynamic SSID IE: ID=0, Length, Payload
                ssid_bytes = ssid.encode('ascii', errors='replace')
                ie_ssid_bytes = b'\x00' + bytes([len(ssid_bytes)]) + ssid_bytes
                
                # 2. Dynamic Vendor IE: ID=221 (0xDD), Length, OUI + Payload
                vendor_info = backend.OUI + vendor_data
                ie_vendor_bytes = b'\xdd' + bytes([len(vendor_info)]) + vendor_info
                
                # 3. Dynamic MAC Header: Frame Control (0x8000), Duration (0x0000), Addr1, Addr2, Addr3, Sequence
                import struct
                mac_bytes = bytes.fromhex(mac_addr.replace(':', ''))
                seq_ctrl = (seq_num << 4) & 0xFFFF
                mac_header_bytes = b'\x80\x00\x00\x00' + dest_bytes + mac_bytes + mac_bytes + struct.pack('<H', seq_ctrl)
                
                # Construct final raw frame in microseconds
                frame = radiotap_bytes + mac_header_bytes + beacon_base_bytes + ie_ssid_bytes + static_ies_bytes + ie_vendor_bytes
                packets.append((mac_addr, frame))

            t_build = time.monotonic() - t_build_start
            backend.build_times.append(t_build)

            if packets:
                for mac_addr, raw_pkt in packets:
                    if not backend._running:
                        break
                    try:
                        t0 = time.monotonic()
                        ts_before = time.time()
                        backend._sock.send(raw_pkt)
                        t_inj = time.monotonic() - t0
                        backend.inject_times.append(t_inj)

                        ts_now = ts_before
                        with backend.lock:
                            if mac_addr not in backend.packets_transmitted:
                                backend.packets_transmitted[mac_addr] = []
                            backend.packets_transmitted[mac_addr].append(ts_now)
                            backend.tx_records.append((cycle_idx, ts_now, mac_addr, "Message Pack"))
                    except Exception as e:
                        logger.debug(f"Wi-Fi transmit error for {mac_addr}: {e}")

            t_loop = time.monotonic() - t_loop_start
            backend.loop_times.append(t_loop)

            next_tick += backend.beacon_interval
            now = time.time()
            if next_tick < now:
                backend.missed_deadlines += 1
                next_tick = now
            else:
                sleep_time = next_tick - now
                if sleep_time > 0:
                    time.sleep(sleep_time)

            backend.current_cycle = getattr(backend, 'current_cycle', 0) + 1
            if getattr(backend, 'max_cycles', None) is not None and backend.current_cycle >= backend.max_cycles:
                logger.info(f"Target of {backend.max_cycles} Wi-Fi transmission cycles reached ({backend.current_cycle - 2} eval + 2 buffer); stopping loop.")
                backend._running = False
                for d in getattr(backend, '_drones', []):
                    d.active = False
                break
    backend._transmit_loop = patched_transmit_loop


def run_experiment(tx_iface: str, rx_iface: str, num_drones: int, duration: float, interval: float, rate_mbps: float = 1.0, no_self_id: bool = True, no_operator_id: bool = False, channel: int = 6):
    args = argparse.Namespace(
        interface=tx_iface,
        manual=False,
        random=num_drones,
        serial=None,
        interval=1.0,  # Default main loop (kinematics) update interval to match normal spoofer
        location=(473763399, 85312562),
        verbose=False,
        transport="wifi",
        no_self_id=no_self_id,
        no_operator_id=no_operator_id,
        drones_config=[]
    )

    # Lock interfaces to target channel
    for iface in [tx_iface, rx_iface]:
        try:
            subprocess.run(["sudo", "iw", "dev", iface, "set", "channel", str(channel)], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"Could not set channel {channel} on {iface}: {e}")

    # Calculate exact target evaluation cycles plus 2 buffer cycles
    target_cycles = int(round(duration / interval)) + 2
    # Set wall-clock lifespan ceiling to a generous safety duration so evaluation is governed strictly by loop cycle count
    safety_duration = max(300.0, (duration + (2.0 * interval)) * 5.0)
    drones_config = []
    base_lat, base_lng = args.location
    for _ in range(num_drones):
        lat, lng = random_location(base_lat, base_lng, 50000)
        drones_config.append({
            "mode": "random",
            "start_location": [lat / 1e7, lng / 1e7],
            "lifespan_seconds": safety_duration,
        })
    args.drones_config = drones_config

    is_soc = channel in (6, 149)
    ch_label = f"Social Channel {channel}" if is_soc else f"Non-Social Channel {channel}"
    logger.info(f"=== Starting Wi-Fi Experiment: [{ch_label}], Drones={num_drones}, Interval={interval}s ({1.0/interval:.1f}Hz), Target Cycles={target_cycles}, Rate={rate_mbps}Mbps ===")

    # Start sniffers with a massive timeout ceiling so they are controlled explicitly by the stop_filter lifecycle
    sniffer_timeout = 10000.0
    rx_sniffer = SnifferThread(rx_iface, sniffer_timeout, "RX-Air")
    tx_sniffer = SnifferThread(tx_iface, sniffer_timeout, "TX-Monitor")
    rx_sniffer.start()
    tx_sniffer.start()

    time.sleep(1.0)
    logger.info(f"Sniffers active and listening on channel {channel}.")

    backend = WifiBackend(interface=tx_iface, beacon_interval=interval, rate_mbps=rate_mbps, channel=channel)
    instrument_backend(backend, max_cycles=target_cycles)

    spoofer = DroneSpoofer(args, [backend])
    t_start = time.time()
    try:
        spoofer.run_automatic_mode()
    finally:
        backend.close()
    t_end = time.time()

    logger.info("Waiting for sniffer packet buffers to drain...")
    settled_start = time.time()
    last_count = -1
    while time.time() - settled_start < 5.0:
        with rx_sniffer.lock:
            current_count = len(rx_sniffer.raw_records)
        if current_count != last_count:
            last_count = current_count
            settled_start = time.time()
        time.sleep(0.5)
        if time.time() - settled_start >= 2.0 and current_count > 0:
            break
            
    rx_sniffer.running = False
    tx_sniffer.running = False
    rx_sniffer.join(timeout=2.0)
    tx_sniffer.join(timeout=2.0)
    
    actual_duration = t_end - t_start
    if getattr(backend, 'missed_deadlines', 0) > 0:
        logger.debug(f"Tracked {backend.missed_deadlines} missed deadlines.")

    # Analysis & MAC Correlation using strict Cycle Indexing (preventing bucket jumping on missed deadlines)
    num_buckets = int(round(duration / interval))

    mac_to_serial: Dict[str, str] = getattr(backend, 'registered_drones', {})

    valid_expected = [(ts, mac, mtype, cyc) for cyc, ts, mac, mtype in getattr(backend, 'expected_records', []) if 0 <= cyc < num_buckets]
    valid_tx = [(ts, mac, mtype, cyc) for cyc, ts, mac, mtype in getattr(backend, 'tx_records', []) if 0 <= cyc < num_buckets]

    expected_by_mac: Dict[str, int] = {mac: 0 for mac in mac_to_serial.keys()}
    msg_type_stats: Dict[str, Dict[str, int]] = {}

    def get_stat_dict():
        return {"expected": 0, "tx_sent": 0, "rx_sniffed": 0}

    expected_buckets = [0] * num_buckets
    tx_buckets = [0] * num_buckets
    rx_buckets = [0] * num_buckets
    real_time_sums = [0.0] * num_buckets
    real_time_counts = [0] * num_buckets

    for ts, mac, mtype, cyc in valid_expected:
        if mac in expected_by_mac:
            expected_by_mac[mac] += 1
        if mtype not in msg_type_stats:
            msg_type_stats[mtype] = get_stat_dict()
        msg_type_stats[mtype]["expected"] += 1
        if 0 <= cyc < num_buckets:
            expected_buckets[cyc] += 1

    expected_total_packets = sum(expected_by_mac.values())

    filtered_tx: Dict[str, List[float]] = {mac: [] for mac in mac_to_serial.keys()}
    tx_items_by_mac: Dict[str, List[Dict[str, Any]]] = {mac: [] for mac in mac_to_serial.keys()}

    for ts, mac, mtype, cyc in valid_tx:
        if mac in filtered_tx:
            filtered_tx[mac].append(ts)
            tx_items_by_mac[mac].append({"ts_tx": ts, "mtype": mtype, "cycle": cyc, "matched_rx_ts": None})
        if mtype not in msg_type_stats:
            msg_type_stats[mtype] = get_stat_dict()
        msg_type_stats[mtype]["tx_sent"] += 1
        if 0 <= cyc < num_buckets:
            tx_buckets[cyc] += 1
            real_time_sums[cyc] += (ts - t_start)
            real_time_counts[cyc] += 1

    real_time_buckets = [0.0] * num_buckets
    for i in range(num_buckets):
        if real_time_counts[i] > 0:
            real_time_buckets[i] = real_time_sums[i] / real_time_counts[i]

    backend.packets_transmitted = filtered_tx
    total_tx_received = sum(len(times) for times in backend.packets_transmitted.values())

    def get_percentiles(vals):
        if not vals:
            return {"min": 0.0, "p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0, "avg": 0.0}
        s = sorted(vals)
        n = len(s)
        return {
            "min": s[0],
            "p50": s[int((n - 1) * 0.50)],
            "p95": s[int((n - 1) * 0.95)],
            "p99": s[int((n - 1) * 0.99)],
            "max": s[-1],
            "avg": sum(s) / n
        }

    pdu_type_counts: Dict[str, int] = {"Beacon": 0}
    drone_payload_counts: Dict[str, Dict[str, int]] = {
        mac: {"basic_id": 0, "location": 0, "system": 0, "operator_id": 0, "complete_packs": 0, "total_rx": 0}
        for mac in mac_to_serial.keys()
    }
    
    total_complete_packs = 0
    total_air_bytes = 0
    matched_rx_by_mac: Dict[str, List[float]] = {mac: [] for mac in mac_to_serial.keys()}
    propagation_latencies_ms = []

    with rx_sniffer.lock:
        sorted_records = sorted(rx_sniffer.raw_records, key=lambda x: x.get("timestamp", 0))
        for rec in sorted_records:
            mac = rec.get("mac", "").upper()
            if mac not in tx_items_by_mac:
                continue
            ts_rx = rec.get("timestamp", 0)

            rx_types = []
            msgs = rec.get("parsed_messages", [])
            for m in msgs:
                rx_types.append(m.get("type", "Unknown"))
                
            # Strictly correlate against an unmatched TX transmission within [-0.05s, +3.0s] window
            matched_tx = None
            for tx_item in tx_items_by_mac[mac]:
                if tx_item["matched_rx_ts"] is None and (tx_item["ts_tx"] - 0.05 <= ts_rx <= tx_item["ts_tx"] + 3.0):
                    if tx_item["mtype"] in rx_types or tx_item["mtype"] == "Message Pack":
                        matched_tx = tx_item
                        break
            
            if matched_tx is not None:
                matched_tx["matched_rx_ts"] = ts_rx
                matched_rx_by_mac[mac].append(ts_rx)
                propagation_latencies_ms.append((ts_rx - matched_tx["ts_tx"]) * 1000.0)
                cyc = matched_tx["cycle"]
                if 0 <= cyc < num_buckets:
                    rx_buckets[cyc] += 1

                mtype = matched_tx["mtype"]
                if mtype not in msg_type_stats:
                    msg_type_stats[mtype] = get_stat_dict()
                msg_type_stats[mtype]["rx_sniffed"] += 1

                pdu_type_counts["Beacon"] += 1
                total_air_bytes += rec.get("raw_length", 0)

                msgs = rec.get("parsed_messages", [])
                has_basic_id = False
                has_loc = False
                for m in msgs:
                    mt = m.get("type", "")
                    if mt == "Basic ID":
                        expected_serial = mac_to_serial.get(mac, "")
                        if not expected_serial or m.get("id") == expected_serial:
                            drone_payload_counts[mac]["basic_id"] += 1
                            has_basic_id = True
                    elif mt == "Location":
                        drone_payload_counts[mac]["location"] += 1
                        has_loc = True
                    elif mt == "System":
                        drone_payload_counts[mac]["system"] += 1
                    elif mt == "Operator ID":
                        drone_payload_counts[mac]["operator_id"] += 1
                if has_basic_id and has_loc:
                    drone_payload_counts[mac]["complete_packs"] += 1
                    total_complete_packs += 1

    total_rx_received = sum(len(times) for times in matched_rx_by_mac.values())

    # Inter-Arrival Time (IAT) calculation
    all_iats_ms = []
    jitter_list = []
    for mac, times in matched_rx_by_mac.items():
        count = len(times)
        if count > 1:
            sorted_times = sorted(times)
            intervals = [(sorted_times[i] - sorted_times[i-1]) * 1000 for i in range(1, count)]
            all_iats_ms.extend(intervals)
            if len(intervals) > 1:
                jitter_list.append(statistics.stdev([x / 1000 for x in intervals]))

    pdr_tx = (total_tx_received / expected_total_packets) * 100 if expected_total_packets > 0 else 0
    pdr_rx = (total_rx_received / expected_total_packets) * 100 if expected_total_packets > 0 else 0
    complete_pack_ratio = (total_complete_packs / total_rx_received * 100) if total_rx_received > 0 else 0

    inject_stats = get_percentiles([t * 1000 for t in backend.inject_times] if getattr(backend, 'inject_times', None) else [])
    build_stats = get_percentiles([t * 1000 for t in backend.build_times] if getattr(backend, 'build_times', None) else [])
    loop_stats = get_percentiles([t * 1000 for t in backend.loop_times] if getattr(backend, 'loop_times', None) else [])
    iat_stats = get_percentiles(all_iats_ms)
    propagation_stats = get_percentiles(propagation_latencies_ms)
    avg_jitter = statistics.mean(jitter_list) if jitter_list else 0

    per_drone_stats = []
    drones_with_rx = 0
    for mac, serial in mac_to_serial.items():
        tx_cnt = len(backend.packets_transmitted.get(mac, []))
        rx_cnt = len(matched_rx_by_mac.get(mac, []))
        exp_cnt = expected_by_mac.get(mac, int(duration / interval))
        pdr_drone = (rx_cnt / exp_cnt * 100) if exp_cnt > 0 else 0
        if rx_cnt > 0:
            drones_with_rx += 1
        d_pld = drone_payload_counts.get(mac, {"basic_id": 0, "location": 0, "system": 0, "operator_id": 0, "complete_packs": 0, "total_rx": rx_cnt})
        per_drone_stats.append({
            "serial": serial,
            "mac": mac,
            "expected": exp_cnt,
            "tx_sent": tx_cnt,
            "rx_sniffed": rx_cnt,
            "pdr_percent": pdr_drone,
            "basic_id_count": d_pld["basic_id"],
            "location_count": d_pld["location"],
            "system_count": d_pld["system"],
            "operator_id_count": d_pld["operator_id"],
            "complete_packs": d_pld["complete_packs"]
        })

    logger.info(f"--- Results for {num_drones} drones ---")
    logger.info(f"Expected Packets (Staggering Scheduled): {expected_total_packets}")
    logger.info(f"TX Sent Packets (Kernel): {total_tx_received} ({pdr_tx:.2f}% injected to kernel)")
    logger.info(f"RX Sniffed Packets (Air): {total_rx_received} ({pdr_rx:.2f}% over-the-air delivery)")
    logger.info(f"Drones Active with Air Payload Delivery: {drones_with_rx}/{num_drones} ({ (drones_with_rx/num_drones*100) if num_drones > 0 else 0:.1f}%)")
    logger.info(f"Complete RID Message Packs (Basic ID + Location): {total_complete_packs} ({complete_pack_ratio:.1f}% of sniffed packets)")
    logger.info(f"Propagation Latency (t_air - t_kernel): Avg={propagation_stats['avg']:.2f}ms, p50={propagation_stats['p50']:.2f}ms, p95={propagation_stats['p95']:.2f}ms")
    logger.info(f"Inter-Arrival Time (IAT): Avg={iat_stats['avg']:.2f}ms, p50={iat_stats['p50']:.2f}ms, p95={iat_stats['p95']:.2f}ms, Jitter={avg_jitter*1000:.2f}ms")
    logger.info(f"Execution Times: Build Avg={build_stats['avg']:.2f}ms | Inject Avg={inject_stats['avg']:.2f}ms (p95={inject_stats['p95']:.2f}ms) | Loop Avg={loop_stats['avg']:.2f}ms")
    logger.info(f"Missed Deadlines: {backend.missed_deadlines}")

    return {
        "drones": num_drones,
        "duration": duration,
        "interval": interval,
        "rate_mbps": rate_mbps,
        "expected_packets": expected_total_packets,
        "tx_received_packets": total_tx_received,
        "rx_received_packets": total_rx_received,
        "pdr_tx_percent": pdr_tx,
        "pdr_rx_percent": pdr_rx,
        "complete_pack_ratio_percent": complete_pack_ratio,
        "drones_with_rx_count": drones_with_rx,
        "avg_jitter_ms": avg_jitter * 1000,
        "inject_stats_ms": inject_stats,
        "build_stats_ms": build_stats,
        "loop_stats_ms": loop_stats,
        "iat_stats_ms": iat_stats,
        "propagation_latency_stats_ms": propagation_stats,
        "missed_deadlines": backend.missed_deadlines,
        "msg_type_stats": msg_type_stats,
        "inject_times_ms": [t * 1000 for t in backend.inject_times] if hasattr(backend, 'inject_times') else [],
        "per_cycle_stats": {
            "cycle_interval_s": interval,
            "expected": expected_buckets,
            "tx_sniffed": tx_buckets,
            "rx_sniffed": rx_buckets,
            "real_times_s": real_time_buckets
        },
        "per_second_stats": {
            "cycle_interval_s": interval,
            "expected": expected_buckets,
            "tx_sniffed": tx_buckets,
            "rx_sniffed": rx_buckets
        },
        "msg_type_stats": msg_type_stats,
        "channel": channel,
        "is_social_channel": (channel in (6, 149)),
        "per_drone_stats": per_drone_stats,
        "pdu_type_counts": pdu_type_counts,
        "total_air_bytes": total_air_bytes,
        "raw_data": {
            "inject_times_ms": [t * 1000 for t in getattr(backend, 'inject_times', [])],
            "build_times_ms": [t * 1000 for t in getattr(backend, 'build_times', [])],
            "loop_times_ms": [t * 1000 for t in getattr(backend, 'loop_times', [])],
            "propagation_latencies_ms": propagation_latencies_ms,
            "iat_intervals_ms": all_iats_ms,
            "tx_timestamps": {mac: list(times) for mac, times in backend.packets_transmitted.items()},
            "rx_timestamps": {mac: list(times) for mac, times in matched_rx_by_mac.items()}
        },
        "performance": {
            "missed_deadlines": getattr(backend, 'missed_deadlines', 0),
            "actual_duration": actual_duration,
            "requested_duration": duration
        }
    }


def parse_drones_spec(spec: str) -> List[int]:
    """
    Parse a flexible drone count specification string.
    Supports:
      - Comma separated list: "10,20,50,100"
      - Range with step: "40-1000:20" (40 to 1000 in steps of 20)
      - Mixed formats: "10, 20, 40-200:20, 250-500:50"
    """
    res = []
    chunks = [c.strip() for c in spec.split(",") if c.strip()]
    for chunk in chunks:
        if "-" in chunk and not chunk.startswith("-"):
            parts = chunk.split("-")
            start = int(parts[0].strip())
            if ":" in parts[1]:
                end_str, step_str = parts[1].split(":")
                end = int(end_str.strip())
                step = int(step_str.strip())
            else:
                end = int(parts[1].strip())
                step = 10 if end <= 100 else 20
            res.extend(list(range(start, end + 1, step)))
        else:
            res.append(int(chunk))
    return sorted(list(set(res)))


def main():
    parser = argparse.ArgumentParser(description="Evaluate Wi-Fi (ASTM F3411) Capacity and Social vs Non-Social Channel Performance (2.4 GHz & 5 GHz)")
    parser.add_argument("--tx-iface", required=True, help="Transmit wireless interface (e.g. wlan0)")
    parser.add_argument("--rx-iface", required=True, help="Monitor interface for sniffing (e.g. wlan1)")
    parser.add_argument("--drones", type=str, default="10,20,40,60,80,100,120,140,160,180,200,220,240,260,280,300,350,400,450,500,550,600,650,700,750,800,850,900,950,1000", help="Comma separated list or range (e.g. 10-1000:20 or 10,20,40) of drone counts to sweep")
    parser.add_argument("--consecutive-misses", type=int, default=2, help="Terminate sweep early when 100%% of deadlines are missed for N consecutive drone counts (default: 2; 0 to disable)")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration per test in seconds")
    parser.add_argument("--interval", type=float, default=1.0, help="Beacon transmission interval for standard run (default: 1.0s / 1 Hz)")
    parser.add_argument("--channel", type=int, default=6, help="Wi-Fi channel (default: 6 for 2.4GHz social channel, 149 for 5.8GHz social channel)")
    parser.add_argument("--rate", type=float, default=None, help="Wi-Fi transmission rate in Mbps (defaults: 1.0 Mbps for 2.4GHz, 6.0 Mbps for 5.8GHz/5GHz)")
    parser.add_argument("--with-self-id", action="store_false", dest="no_self_id", default=True, help="Enable Self ID message")
    parser.add_argument("--no-operator-id", action="store_true", help="Disable Operator ID message")
    parser.add_argument("--compare-channels", action="store_true", help="Compare Social Channel (Ch 6 @ 2.4GHz or Ch 149 @ 5.8GHz) vs Non-Social Channel @ higher frequency")
    parser.add_argument("--non-social-channel", type=int, default=None, help="Non-social channel to compare against (default: 1 for 2.4GHz, 157 for 5.8GHz)")
    parser.add_argument("--non-social-interval", type=float, default=0.2048, help="Transmission interval for non-social channel in seconds (default: 0.2048s / 200 TUs)")
    parser.add_argument("--out", type=str, default="wifi_capacity_results.json", help="Output JSON file")
    parser.add_argument("--append", action="store_true", help="Append/merge new runs into existing output JSON file if it exists")

    args = parser.parse_args()
    drone_counts = parse_drones_spec(args.drones)

    if args.non_social_channel is None:
        args.non_social_channel = 157 if (args.channel in (149, 153, 157, 161, 165) or args.channel >= 36) else 1

    results = []

    def sweep_channel(channel: int, interval_val: float, phase_desc: str) -> List[dict]:
        phase_results = []
        consecutive_full_misses = 0
        target_cycles = int(round(args.duration / interval_val))
        effective_rate = args.rate if args.rate is not None else (6.0 if channel >= 36 else 1.0)

        for idx, count in enumerate(drone_counts):
            res = run_experiment(
                args.tx_iface, args.rx_iface, count, args.duration, interval_val,
                effective_rate, args.no_self_id, args.no_operator_id, channel=channel
            )
            phase_results.append(res)
            results.append(res)

            actual_cycles = len(res.get("raw_data", {}).get("loop_times_ms", [])) or target_cycles
            missed = res.get("missed_deadlines", res.get("performance", {}).get("missed_deadlines", 0))
            is_full_miss = (missed >= actual_cycles) or (missed >= target_cycles)

            if is_full_miss:
                consecutive_full_misses += 1
                logger.warning(
                    f"[{phase_desc}] {count} drones: 100% of deadlines missed ({missed}/{actual_cycles} cycles). "
                    f"Consecutive full-miss runs: {consecutive_full_misses}/{args.consecutive_misses}"
                )
            else:
                if consecutive_full_misses > 0:
                    logger.info(f"[{phase_desc}] {count} drones completed within deadlines ({missed}/{actual_cycles} missed). Resetting consecutive miss counter.")
                consecutive_full_misses = 0

            if args.consecutive_misses > 0 and consecutive_full_misses >= args.consecutive_misses:
                logger.warning(
                    f"[{phase_desc}] Auto-terminating sweep early at {count} drones: {args.consecutive_misses} consecutive runs "
                    f"missed 100% of deadlines ({missed}/{actual_cycles} cycles). Capacity ceiling reached for Channel {channel} ({interval_val}s interval)!"
                )
                break

            if idx < len(drone_counts) - 1:
                logger.info("Cooldown before next experiment...")
                time.sleep(5.0)

        return phase_results

    if args.compare_channels:
        social_ch = args.channel
        s_is_soc = social_ch in (6, 149)
        s_band = "5.8GHz" if social_ch in (149, 153, 157, 161, 165) or social_ch >= 149 else ("5.2GHz" if social_ch >= 36 else "2.4GHz")
        social_label = f"Social Channel {social_ch} ({s_band})" if s_is_soc else f"Channel {social_ch} ({s_band})"
        logger.info("=== Starting Channel Performance Comparison Sweep ===")
        logger.info(f"Phase 1: {social_label} (Interval={args.interval}s / {1.0/args.interval:.1f}Hz)")
        social_results = sweep_channel(social_ch, args.interval, social_label)

        ns_ch = args.non_social_channel
        ns_band = "5.8GHz" if ns_ch in (149, 153, 157, 161, 165) or ns_ch >= 149 else ("5.2GHz" if ns_ch >= 36 else "2.4GHz")
        ns_label = f"Non-Social Channel {ns_ch} ({ns_band})"
        logger.info(f"\nPhase 2: {ns_label} High-Frequency (Interval={args.non_social_interval}s / {1.0/args.non_social_interval:.1f}Hz)")
        non_social_results = sweep_channel(ns_ch, args.non_social_interval, ns_label)

        # Print Side-by-Side Comparison Summary Table
        ns_freq_hz = 1.0 / args.non_social_interval
        s_freq_hz = 1.0 / args.interval
        print("\n" + "="*145)
        print(f"COMPARATIVE SUMMARY: {social_label} ({args.interval}s / {s_freq_hz:.1f}Hz) vs {ns_label} ({args.non_social_interval}s / {ns_freq_hz:.1f}Hz)")
        print("="*145)
        print(f"{'Drones':<8} | {'Social PDR':<12} | {'Non-Social PDR':<16} | {'Social Missed':<14} | {'Non-Social Missed':<18} | {'Social Inj(ms)':<15} | {'Non-Social Inj(ms)'}")
        print("-" * 145)
        all_drones_sweep = sorted(list(set([r["drones"] for r in social_results + non_social_results])))
        s_map = {r["drones"]: r for r in social_results}
        ns_map = {r["drones"]: r for r in non_social_results}
        for d in all_drones_sweep:
            s_res = s_map.get(d)
            ns_res = ns_map.get(d)
            s_pdr = f"{s_res['pdr_rx_percent']:.2f}%" if s_res else "STOPPED"
            ns_pdr = f"{ns_res['pdr_rx_percent']:.2f}%" if ns_res else "STOPPED"
            s_miss = str(s_res['missed_deadlines']) if s_res else "-"
            ns_miss = str(ns_res['missed_deadlines']) if ns_res else "-"
            s_inj = f"{s_res['inject_stats_ms']['avg']:.2f}" if s_res else "-"
            ns_inj = f"{ns_res['inject_stats_ms']['avg']:.2f}" if ns_res else "-"
            print(f"{d:<8} | {s_pdr:<12} | {ns_pdr:<16} | {s_miss:<14} | {ns_miss:<18} | {s_inj:<15} | {ns_inj}")
        print("="*145 + "\n")

    else:
        sweep_channel(args.channel, args.interval, f"Channel {args.channel}")

    # Save JSON results (structured by channel if comparative or if appending to comparative)
    out_payload = results
    if args.append and os.path.exists(args.out):
        try:
            with open(args.out, 'r') as f:
                existing_data = json.load(f)

            if isinstance(existing_data, dict) and ("social_channel" in existing_data or "non_social_channel" in existing_data or "all_runs" in existing_data):
                existing_social = existing_data.get("social_channel", [])
                existing_non_social = existing_data.get("non_social_channel", [])

                for res in results:
                    is_social = res.get("is_social_channel", (res.get("channel") in (6, 149)))
                    target_list = existing_social if is_social else existing_non_social

                    matched_idx = -1
                    for idx, item in enumerate(target_list):
                        if item.get("drones") == res.get("drones") and item.get("channel") == res.get("channel") and abs(item.get("interval", 0) - res.get("interval", 0)) < 1e-4:
                            matched_idx = idx
                            break
                    if matched_idx >= 0:
                        target_list[matched_idx] = res
                    else:
                        target_list.append(res)

                existing_social.sort(key=lambda x: x.get("drones", 0))
                existing_non_social.sort(key=lambda x: x.get("drones", 0))
                all_runs = existing_social + existing_non_social
                out_payload = {
                    "social_channel": existing_social,
                    "non_social_channel": existing_non_social,
                    "all_runs": all_runs
                }
                results = all_runs
                logger.info(f"Successfully appended/merged new runs into existing structured dataset ({len(results)} total runs)")
            elif isinstance(existing_data, list):
                merged_list = list(existing_data)
                for res in results:
                    matched_idx = -1
                    for idx, item in enumerate(merged_list):
                        if item.get("drones") == res.get("drones") and item.get("channel") == res.get("channel") and abs(item.get("interval", 0) - res.get("interval", 0)) < 1e-4:
                            matched_idx = idx
                            break
                    if matched_idx >= 0:
                        merged_list[matched_idx] = res
                    else:
                        merged_list.append(res)
                merged_list.sort(key=lambda x: (x.get("channel", 0), x.get("drones", 0)))
                if args.compare_channels:
                    out_payload = {
                        "social_channel": [r for r in merged_list if r.get("is_social_channel", False)],
                        "non_social_channel": [r for r in merged_list if not r.get("is_social_channel", False)],
                        "all_runs": merged_list
                    }
                else:
                    out_payload = merged_list
                results = merged_list
                logger.info(f"Successfully appended/merged new runs into existing flat list ({len(results)} total runs)")
        except Exception as e:
            logger.error(f"Error loading existing file {args.out} for appending: {e}. Saving current runs.")
            if args.compare_channels:
                out_payload = {
                    "social_channel": [r for r in results if r.get("is_social_channel", False)],
                    "non_social_channel": [r for r in results if not r.get("is_social_channel", False)],
                    "all_runs": results
                }
            else:
                out_payload = results
    else:
        if args.compare_channels:
            out_payload = {
                "social_channel": [r for r in results if r.get("is_social_channel", False)],
                "non_social_channel": [r for r in results if not r.get("is_social_channel", False)],
                "all_runs": results
            }
        else:
            out_payload = results

    with open(args.out, 'w') as f:
        json.dump(out_payload, f, indent=4)

    logger.info(f"Saved complete results to {args.out}")

    # Print main summary table with Channel & Interval columns
    print("\n" + "="*145)
    print(f"{'Drones':<8} | {'Channel':<10} | {'Interval':<10} | {'Expected':<9} | {'TX Sent':<9} | {'RX Sniffed':<11} | {'PDR (Air)':<10} | {'Latency(ms)':<11} | {'Jitter(ms)':<11} | {'Inject(ms)':<10} | {'Missed':<7}")
    print("-" * 145)
    for r in results:
        p_stat = r.get("propagation_latency_stats_ms", {"avg": 0.0})
        ch_str = f"Ch {r.get('channel', 6)}" + (" (Social)" if r.get("is_social_channel", False) else "")
        inv_str = f"{r['interval']:.3f}s"
        print(f"{r['drones']:<8} | {ch_str:<10} | {inv_str:<10} | {r['expected_packets']:<9} | {r['tx_received_packets']:<9} | {r['rx_received_packets']:<11} | {r['pdr_rx_percent']:<9.2f}% | {p_stat['avg']:<11.2f} | {r['avg_jitter_ms']:<11.2f} | {r['inject_stats_ms']['avg']:<10.2f} | {r.get('missed_deadlines', 0):<7}")
    print("="*145 + "\n")

    # Print per-drone breakdowns labeled by channel & interval
    for r in results:
        ch_str = f"Channel {r.get('channel', 6)}" + (" (Social)" if r.get("is_social_channel", False) else "")
        print(f"--- Per-Drone Remote ID Breakdown [{ch_str} @ {r['interval']}s] ({r['drones']} Drones) ---")
        print(f"{'Drone Serial':<25} | {'MAC Address':<18} | {'Expected':<10} | {'TX Sent':<10} | {'RX (Air)':<10} | {'PDR (Air)':<10} | {'Loc(RX)':<9} | {'BasicID(RX)':<11} | {'Complete RID'}")
        print("-" * 135)
        for d in r["per_drone_stats"]:
            print(f"{d['serial']:<25} | {d['mac']:<18} | {d['expected']:<10} | {d['tx_sent']:<10} | {d['rx_sniffed']:<10} | {d['pdr_percent']:<9.2f}% | {d['location_count']:<9} | {d['basic_id_count']:<11} | {d['complete_packs']}")
        print("\n")

    # Print ASTM Message Type delivery statistics labeled by channel & interval
    for r in results:
        ch_str = f"Channel {r.get('channel', 6)}"
        print(f"--- ASTM Message Delivery Stats [{ch_str} @ {r['interval']}s] ({r['drones']} Drones) ---")
        print(f"{'Message Type':<18} | {'Expected':<12} | {'TX Sent (Kern)':<15} | {'RX Sniffed (Air)':<18} | {'Delivery Rate (Air)'}")
        print("-" * 90)
        for mtype, s in r.get("msg_type_stats", {}).items():
            dr = f"{(s['rx_sniffed'] / s['expected'] * 100):.2f}%" if s["expected"] > 0 else "-"
            print(f"{mtype:<18} | {s['expected']:<12} | {s['tx_sent']:<15} | {s['rx_sniffed']:<18} | {dr}")
        print("\n")

    # Print per-cycle breakdowns labeled by channel & interval
    for r in results:
        ch_str = f"Channel {r.get('channel', 6)}" + (" (Social)" if r.get("is_social_channel", False) else "")
        print(f"--- Per-Cycle Breakdown [{ch_str} @ {r['interval']}s] for {r['drones']} Drones ---")
        print(f"{'Cycle (Step)':<14} | {'Sched (s)':<10} | {'Real (s)':<10} | {'Expected':<9} | {'TX Sent':<9} | {'RX Sniffed':<11} | {'Dropped (Kern)':<15} | {'Dropped (Air)':<15}")
        print("-" * 115)

        cycle_stats = r.get("per_cycle_stats", r.get("per_second_stats", {}))
        expected = cycle_stats.get("expected", [])
        tx = cycle_stats.get("tx_sniffed", [])
        rx = cycle_stats.get("rx_sniffed", [])
        reals = cycle_stats.get("real_times_s", [])
        inv = r["interval"]

        for i in range(len(expected)):
            if expected[i] == 0 and tx[i] == 0 and rx[i] == 0:
                continue
            drop_kern = expected[i] - tx[i] if expected[i] > 0 else 0
            drop_air = tx[i] - rx[i] if tx[i] > 0 else 0
            sched_s = i * inv
            real_val = f"{reals[i]:.3f}" if i < len(reals) and tx[i] > 0 else "-"
            print(f"cyc={i:<10} | {sched_s:<10.3f} | {real_val:<10} | {expected[i]:<9} | {tx[i]:<9} | {rx[i]:<11} | {drop_kern:<15} | {drop_air:<15}")
        print("="*115 + "\n")

    # Generate Plots (separated per channel + side-by-side comparative figure)
    try:
        import matplotlib.pyplot as plt

        # Group results by channel
        channels_map = {}
        for r in results:
            ch = r.get("channel", 6)
            if ch not in channels_map:
                channels_map[ch] = []
            channels_map[ch].append(r)

        # 1. Generate dedicated standalone plot per channel
        for ch, ch_results in channels_map.items():
            plt.figure(figsize=(10, 6))
            has_data = False
            for r in ch_results:
                drones = r["drones"]
                inv = r["interval"]
                times = r.get("raw_data", {}).get("inject_times_ms", [])
                if times:
                    plt.plot(times, marker='o', label=f"{drones} Drones ({inv}s interval)")
                    has_data = True

            if has_data:
                ch_label = f"Channel {ch} (Social)" if ch == 6 else f"Channel {ch} (Non-Social)"
                plt.xlabel("Packet Index")
                plt.ylabel("Raw Socket send() Execution Time (ms)")
                plt.title(f"Wi-Fi Raw Socket send() Execution Time per Packet [{ch_label}]")
                plt.legend()
                plt.grid(True)

                ch_plot_file = args.out.replace(".json", f"_channel_{ch}_plot.png")
                if not ch_plot_file.endswith(".png"):
                    ch_plot_file += f"_channel_{ch}_plot.png"
                plt.savefig(ch_plot_file)
                plt.close()
                logger.info(f"Saved dedicated channel plot to {ch_plot_file}")

        # 2. If multiple channels are present, generate a side-by-side comparative figure
        if len(channels_map) > 1:
            fig, axes = plt.subplots(1, len(channels_map), figsize=(7 * len(channels_map), 6), sharey=True)
            axes_list = list(axes) if hasattr(axes, '__iter__') else [axes]

            for idx, (ch, ch_results) in enumerate(channels_map.items()):
                ax = axes_list[idx]
                ch_label = f"Channel {ch} (Social)" if ch == 6 else f"Channel {ch} (Non-Social)"
                for r in ch_results:
                    drones = r["drones"]
                    inv = r["interval"]
                    times = r.get("raw_data", {}).get("inject_times_ms", [])
                    if times:
                        ax.plot(times, marker='o', label=f"{drones} Drones ({inv}s)")
                ax.set_xlabel("Packet Index")
                if idx == 0:
                    ax.set_ylabel("Raw Socket send() Execution Time (ms)")
                ax.set_title(f"{ch_label}")
                ax.legend()
                ax.grid(True)

            plt.suptitle("Wi-Fi Socket Execution Time Comparison across Channels", fontsize=14)
            plt.tight_layout()
            comp_plot_file = args.out.replace(".json", "_comparison_plot.png")
            if not comp_plot_file.endswith(".png"):
                comp_plot_file += "_comparison_plot.png"
            plt.savefig(comp_plot_file)
            plt.close()
            logger.info(f"Saved side-by-side channel comparison plot to {comp_plot_file}")

    except ImportError:
        logger.warning("matplotlib not installed. Skipping plot generation. Time series data is saved in JSON.")

    # Finally, print the massive red-flag missed deadline warnings at the absolute end so they are not hidden
    total_missed = sum(r.get("performance", {}).get("missed_deadlines", 0) for r in results)
    if total_missed > 0:
        print("\n\n")
        logger.warning("==========================================================================")
        logger.warning(f"CRITICAL PERFORMANCE ALERT: Wi-Fi Backend Missed {total_missed} Deadlines Across Tested Densities!")
        for r in results:
            m = r.get("performance", {}).get("missed_deadlines", 0)
            if m > 0:
                act = r.get('performance', {}).get('actual_duration', 0)
                req = r.get('performance', {}).get('requested_duration', 0)
                ch = r.get("channel", 6)
                cyc_total = len(r.get("raw_data", {}).get("loop_times_ms", []))
                d_cnt = r.get("drones", 0)
                logger.warning(f" -> Channel {ch} ({d_cnt} Drones): Requested {req}s simulation time, but took {act:.2f}s of real wall-clock time! ({m}/{cyc_total} cycles missed deadline)")
        logger.warning("==========================================================================")
        print("\n")
if __name__ == "__main__":
    main()
