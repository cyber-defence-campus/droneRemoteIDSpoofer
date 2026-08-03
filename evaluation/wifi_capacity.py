#!/usr/bin/env python3
import argparse
import json
import logging
import os
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
        logger.info(f"Starting {self.label} sniffer on {self.iface} for {self.duration} seconds...")
        try:
            sniff(iface=self.iface, timeout=self.duration, prn=self.packet_handler, store=False,
                  lfilter=lambda p: p.haslayer(dot11.Dot11Beacon))
        except Exception as e:
            logger.error(f"Error running sniffer on {self.iface}: {e}")
        self.running = False
        logger.info(f"{self.label} sniffer stopped.")

    def packet_handler(self, pkt):
        if not self.running:
            return
            
        try:
            # Check for Vendor Specific IE with our OUI
            ie = pkt.getlayer(dot11.Dot11Elt, ID=221)
            while ie:
                if hasattr(ie, 'info') and ie.info and ie.info.startswith(b'\xfa\x0b\xbc'):
                    mac = pkt.addr2.upper() if pkt.addr2 else "UNKNOWN"
                    ts = time.time()
                    raw_length = len(pkt)
                    
                    parsed_messages = []
                    payload_bytes = ie.info[3:]  # Strip 3-byte OUI
                    
                    # Parse ASTM Remote ID Message Pack payload
                    if len(payload_bytes) >= 5 and payload_bytes[0] == 0x0D:
                        # Byte 0: APP_CODE (0x0D)
                        # Byte 1: Message pack counter
                        # Byte 2: MsgType.PACK (0x0F << 4) | version
                        # Byte 3: Msg Size (0x19 = 25 bytes)
                        # Byte 4: Number of messages in pack
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
                    break
                # Iterate through all remaining IEs
                ie = ie.payload.getlayer(dot11.Dot11Elt, ID=221) if hasattr(ie, 'payload') and hasattr(ie.payload, 'getlayer') else None
        except Exception:
            pass


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

        next_tick = time.time()
        while backend._running:
            t_loop_start = time.monotonic()
            packets = []
            current_tsf = int(time.time() * 1000000) % (2**64)
            cycle_idx = getattr(backend, 'current_cycle', 0)

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
                ie_ssid = dot11.Dot11Elt(ID='SSID', info=ssid)
                ie_rates = dot11.Dot11Elt(ID='Rates', info=backend.SUPPORTED_RATES)
                ie_dsset = dot11.Dot11Elt(ID='DSset', info=bytes([backend.channel]))
                ie_tim = dot11.Dot11Elt(ID='TIM', info=b'\x00\x01\x00\x00')
                ie_erp = dot11.Dot11Elt(ID='ERPinfo', info=b'\x00')
                ie_esr = dot11.Dot11Elt(ID='ESRates', info=backend.EXTENDED_SUPPORTED_RATES)
                ie_vendor = dot11.Dot11Elt(ID=221, info=backend.OUI + vendor_data)

                rate_500kbps = int(backend.rate_mbps * 2)
                radiotap = dot11.RadioTap(present='Rate', Rate=rate_500kbps)
                ies = ie_ssid / ie_rates / ie_dsset / ie_tim / ie_erp / ie_esr / ie_vendor

                dot11_base = dot11.Dot11(
                    type=0, subtype=8,
                    addr1=backend.DEST_ADDR,
                    addr2=mac_addr,
                    addr3=mac_addr,
                    SC=(seq_num << 4)
                )
                beacon_base = dot11.Dot11Beacon(cap='ESS' if backend.ess else 0, timestamp=current_tsf)
                frame = radiotap / dot11_base / beacon_base / ies
                packets.append((mac_addr, bytes(frame)))

            t_build = time.monotonic() - t_build_start
            backend.build_times.append(t_build)

            if packets:
                for mac_addr, raw_pkt in packets:
                    if not backend._running:
                        break
                    try:
                        t0 = time.monotonic()
                        backend._sock.send(raw_pkt)
                        t_inj = time.monotonic() - t0
                        backend.inject_times.append(t_inj)

                        ts_now = time.time()
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


def run_experiment(tx_iface: str, rx_iface: str, num_drones: int, duration: float, interval: float, rate_mbps: float = 1.0, no_self_id: bool = True, no_operator_id: bool = False):
    args = argparse.Namespace(
        interface=tx_iface,
        manual=False,
        random=num_drones,
        serial=None,
        interval=interval,
        location=(473763399, 85312562),
        verbose=False,
        transport="wifi",
        no_self_id=no_self_id,
        no_operator_id=no_operator_id,
        drones_config=[]
    )

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

    logger.info(f"=== Starting Wi-Fi Experiment: Drones={num_drones}, Target Cycles={target_cycles}, Rate={rate_mbps}Mbps ===")

    # Start sniffers
    rx_sniffer = SnifferThread(rx_iface, duration + (4.0 * interval), "RX-Air")
    tx_sniffer = SnifferThread(tx_iface, duration + (4.0 * interval), "TX-Monitor")
    rx_sniffer.start()
    tx_sniffer.start()

    time.sleep(1.0)
    logger.info("Sniffers active and listening on channel 6.")

    backend = WifiBackend(interface=tx_iface, beacon_interval=interval, rate_mbps=rate_mbps)
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

            # Strictly correlate against an unmatched TX transmission within [-0.5s, +3.0s] window
            matched_tx = None
            for tx_item in tx_items_by_mac[mac]:
                if tx_item["matched_rx_ts"] is None and (tx_item["ts_tx"] - 0.5 <= ts_rx <= tx_item["ts_tx"] + 3.0):
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
        "per_second_stats": {
            "expected": expected_buckets,
            "tx_sniffed": tx_buckets,
            "rx_sniffed": rx_buckets
        },
        "msg_type_stats": msg_type_stats,
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
        }
    }


def main():
    parser = argparse.ArgumentParser(description="Evaluate Wi-Fi (ASTM F3411) Capacity")
    parser.add_argument("--tx-iface", required=True, help="Transmit wireless interface (default: wlan0)")
    parser.add_argument("--rx-iface", required=True, help="Monitor interface for sniffing (default: wlan1)")
    parser.add_argument("--drones", type=str, default="10,20,50", help="Comma separated list of drone counts to sweep")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration per test in seconds")
    parser.add_argument("--interval", type=float, default=1.0, help="Beacon transmission interval (default: 1.0s)")
    parser.add_argument("--rate", type=float, default=1.0, help="Wi-Fi transmission rate in Mbps")
    parser.add_argument("--with-self-id", action="store_false", dest="no_self_id", default=True, help="Enable Self ID message")
    parser.add_argument("--no-operator-id", action="store_true", help="Disable Operator ID message")
    parser.add_argument("--out", type=str, default="wifi_capacity_results.json", help="Output JSON file")

    args = parser.parse_args()
    drone_counts = [int(x.strip()) for x in args.drones.split(",")]

    results = []
    for count in drone_counts:
        res = run_experiment(args.tx_iface, args.rx_iface, count, args.duration, args.interval, args.rate, args.no_self_id, args.no_operator_id)
        results.append(res)
        logger.info("Cooldown before next experiment...")
        time.sleep(10.0)

    with open(args.out, 'w') as f:
        json.dump(results, f, indent=4)

    logger.info(f"Saved complete results to {args.out}")

    # Print main summary table
    print("\n" + "="*135)
    print(f"{'Drones':<8} | {'Expected':<10} | {'TX Sent':<10} | {'RX Sniffed':<12} | {'PDR (Air)':<10} | {'Latency(ms)':<12} | {'Jitter(ms)':<12} | {'Inject(ms)':<10} | {'Loop(ms)':<10} | {'Missed':<8}")
    print("-" * 135)
    for r in results:
        p_stat = r.get("propagation_latency_stats_ms", {"avg": 0.0})
        print(f"{r['drones']:<8} | {r['expected_packets']:<10} | {r['tx_received_packets']:<10} | {r['rx_received_packets']:<12} | {r['pdr_rx_percent']:<9.2f}% | {p_stat['avg']:<12.2f} | {r['avg_jitter_ms']:<12.2f} | {r['inject_stats_ms']['avg']:<10.2f} | {r['loop_stats_ms']['avg']:<10.2f} | {r.get('missed_deadlines', 0):<8}")
    print("="*135 + "\n")

    # Print per-drone breakdowns
    for r in results:
        print(f"--- Per-Drone Remote ID Payload Breakdown ({r['drones']} Drones) ---")
        print(f"{'Drone Serial':<25} | {'MAC Address':<18} | {'Expected':<10} | {'TX Sent':<10} | {'RX (Air)':<10} | {'PDR (Air)':<10} | {'Loc(RX)':<9} | {'BasicID(RX)':<11} | {'Complete RID'}")
        print("-" * 135)
        for d in r["per_drone_stats"]:
            print(f"{d['serial']:<25} | {d['mac']:<18} | {d['expected']:<10} | {d['tx_sent']:<10} | {d['rx_sniffed']:<10} | {d['pdr_percent']:<9.2f}% | {d['location_count']:<9} | {d['basic_id_count']:<11} | {d['complete_packs']}")
        print("\n")

    # Print ASTM Message Type delivery statistics
    for r in results:
        print(f"--- ASTM Message Type Delivery Statistics ({r['drones']} Drones) ---")
        print(f"{'Message Type':<18} | {'Expected':<12} | {'TX Sent (Kern)':<15} | {'RX Sniffed (Air)':<18} | {'Delivery Rate (Air)'}")
        print("-" * 90)
        for mtype, s in r.get("msg_type_stats", {}).items():
            dr = f"{(s['rx_sniffed'] / s['expected'] * 100):.2f}%" if s["expected"] > 0 else "-"
            print(f"{mtype:<18} | {s['expected']:<12} | {s['tx_sent']:<15} | {s['rx_sniffed']:<18} | {dr}")
        print("\n")

    # Print per-second breakdowns
    for r in results:
        print(f"--- Per-Second Breakdown for {r['drones']} Drones ---")
        print(f"{'Second':<8} | {'Expected':<10} | {'TX Sent':<12} | {'RX Sniffed':<12} | {'Dropped (Kern)':<15} | {'Dropped (Air)':<15}")
        print("-" * 80)

        expected = r["per_second_stats"]["expected"]
        tx = r["per_second_stats"]["tx_sniffed"]
        rx = r["per_second_stats"]["rx_sniffed"]

        for i in range(len(expected)):
            if expected[i] == 0 and tx[i] == 0 and rx[i] == 0:
                continue
            drop_kern = expected[i] - tx[i] if expected[i] > 0 else 0
            drop_air = tx[i] - rx[i] if tx[i] > 0 else 0
            print(f"t={i:<6} | {expected[i]:<10} | {tx[i]:<12} | {rx[i]:<12} | {drop_kern:<15} | {drop_air:<15}")
        print("="*95 + "\n")

    # Generate Plot
    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(10, 6))
        has_data = False
        for r in results:
            drones = r["drones"]
            times = r.get("raw_data", {}).get("inject_times_ms", [])
            if times:
                plt.plot(times, marker='o', label=f"{drones} Drones")
                has_data = True

        if has_data:
            plt.xlabel("Packet Index")
            plt.ylabel("sendp() Execution Time (ms)")
            plt.title("Wi-Fi sendp() Execution Time per Packet")
            plt.legend()
            plt.grid(True)

            plot_file = args.out.replace(".json", "_plot.png")
            if not plot_file.endswith(".png"):
                plot_file += "_plot.png"
            plt.savefig(plot_file)
            logger.info(f"Saved Wi-Fi sendp execution time plot to {plot_file}")
    except ImportError:
        logger.warning("matplotlib not installed. Skipping plot generation. Time series data is saved in JSON.")


if __name__ == "__main__":
    main()
