#!/usr/bin/env python3
"""
Evaluate Bluetooth (BLE) Capacity Framework
Modeled after wifi_capacity.py and utilizing nrf_bt_sniffer_json.py as an autonomous
background subprocess to capture over-the-air BLE packets and verify delivery rates
against HCI transmission records by MAC address.
"""

import argparse
import json
import logging
import os
import signal
import statistics
import struct
import subprocess
import sys
import threading
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# Add parent directory to path to import drone_rid_spoofer modules
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from drone_rid_spoofer.spoofer import DroneSpoofer
from drone_rid_spoofer.transport.ble import BleLegacyBackend, BleExtendedBackend
from drone_rid_spoofer.helpers import random_location

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger(__name__)

REMOTE_ID_UUID = b"\xFA\xFF"


def wait_for_sniffer_ready(seconds: int = 5, message: str = "Waiting 5s for nRF sniffer radio to initialize and stabilize on channel..."):
    """
    Displays an interactive countdown in the CLI so the user knows why the test is paused.
    This gives the hardware radio time to complete UART configuration and stabilize on the advertising channel.
    """
    sys.stderr.write(f"\n[*] {message}\n")
    for i in range(seconds, 0, -1):
        sys.stderr.write(f"[*] Stabilizing sniffer... ready in {i}s \r")
        sys.stderr.flush()
        time.sleep(1.0)
    sys.stderr.write("[*] nRF Sniffer ready! Starting experiment.          \n\n")
    sys.stderr.flush()


class NrfSnifferThread(threading.Thread):
    """
    Drives nrf_bt_sniffer_json.py as an autonomous background sniffer subprocess.
    Reads structured JSON records from stdout and compiles reception timestamps by MAC address.
    """
    def __init__(self, nrf_port: Optional[str], rx_pcap: Optional[str] = None, coded: bool = False, print_live: bool = False, ble_mode: str = "extended"):
        super().__init__()
        self.nrf_port = nrf_port
        self.rx_pcap = rx_pcap
        self.coded = coded
        self.print_live = print_live
        self.ble_mode = ble_mode
        self.running = False
        self.ready = False
        self.packets_received: Dict[str, List[float]] = {}
        self.raw_records: List[Dict[str, Any]] = []
        self.lock = threading.Lock()
        self.proc: Optional[subprocess.Popen] = None

    def run(self):
        self.running = True
        logger.info(f"Starting NrfSnifferThread via nrf_bt_sniffer_json.py...")
        
        # Kill lingering processes to release any held UART port locks
        subprocess.run(["killall", "-9", "nrfutil", "nrfutil-ble-sniffer", "nrfutil-ble-sni"], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        time.sleep(0.5)
        
        cmd = [sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "nrf_bt_sniffer_json.py")]
        if self.nrf_port:
            cmd.extend(["--nrf-port", self.nrf_port])
        elif self.rx_pcap and os.path.exists(self.rx_pcap):
            cmd.extend(["--rx-pcap", self.rx_pcap])
            
        cmd.append("--only-rid")  # Ensure we only process packets containing valid ASTM Remote ID payload data
            
        if self.coded:
            cmd.append("--coded")
        if self.ble_mode in ("ble5", "extended", "pure_bt5", "bt5"):
            cmd.append("-b") # Only output Bluetooth 5 extended advertising
            
        try:
            # Redirect stdout to pipe to read stream of JSON lines; stderr remains attached for synchronization messages
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=sys.stderr, start_new_session=True)
            self.ready = True
            
            while self.running and self.proc.poll() is None:
                line = self.proc.stdout.readline()
                if not line:
                    continue
                try:
                    line_str = line.decode('utf-8', errors='replace').strip()
                    if not line_str.startswith("{"):
                        continue
                    record = json.loads(line_str)
                    mac = record.get("mac")
                    ts = record.get("timestamp", time.time())
                    has_rid = record.get("remote_id") is not None
                    if mac and mac != "UNKNOWN" and has_rid:
                        mac_upper = mac.upper()
                        with self.lock:
                            if mac_upper not in self.packets_received:
                                self.packets_received[mac_upper] = []
                            self.packets_received[mac_upper].append(ts)
                            self.raw_records.append(record)
                        if self.print_live:
                            print(line_str)
                            sys.stdout.flush()
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"[-] Failed to start nrf_bt_sniffer_json.py subprocess: {e}")
        finally:
            self.stop_process()
            self.running = False
            logger.info("NrfSnifferThread stopped.")

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


def get_msg_type_name(msg: bytes) -> str:
    if not msg or len(msg) == 0:
        return "Unknown"
    m_type = msg[0] >> 4
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


def instrument_backend(backend, active_macs: Optional[List[str]] = None, max_cycles: Optional[int] = None):
    """Monkey-patch BLE backend to record transmit timestamps and performance metrics by MAC address."""
    if active_macs is None:
        active_macs = []
    backend.inject_times = []
    backend.build_times = []
    backend.loop_times = []
    backend.missed_deadlines = 0
    backend.packets_transmitted: Dict[str, List[float]] = {mac.upper(): [] for mac in active_macs}
    backend.expected_records: List[Tuple[int, float, str, str]] = []
    backend.tx_records: List[Tuple[int, float, str, str]] = []
    backend.buffered_tx_packets = []
    backend.lock = threading.Lock()
    backend._last_ad_payload = b""
    backend._current_drone_mac = ""
    backend._current_msg_type_name = "Unknown"
    backend.current_cycle = 0
    backend.max_cycles = max_cycles
    backend.registered_drones = {}

    orig_start = getattr(backend, 'start', None)
    if orig_start and callable(orig_start):
        def patched_start(drones, packet_builder, *a, **kw):
            for drone in drones:
                if getattr(drone, 'ble_address', None):
                    mac_upper = drone.ble_address.upper()
                    serial_str = drone.serial.decode('utf-8', errors='replace') if isinstance(drone.serial, bytes) else str(drone.serial)
                    backend.registered_drones[mac_upper] = serial_str
                    with backend.lock:
                        if mac_upper not in backend.packets_transmitted:
                            backend.packets_transmitted[mac_upper] = []
            return orig_start(drones, packet_builder, *a, **kw)
        backend.start = patched_start

    orig_set_adv_data = backend._set_advertising_data
    def patched_set_adv_data(*args, **kwargs):
        res = orig_set_adv_data(*args, **kwargs)
        try:
            if isinstance(backend, BleLegacyBackend):
                msg = args[0] if len(args) > 0 else kwargs.get('message', b"")
                counter = args[1] if len(args) > 1 else kwargs.get('counter', 0)
                payload = backend._build_legacy_ad(msg, counter)
                backend._current_msg_type_name = get_msg_type_name(msg)
            else:
                payload = args[1] if len(args) > 1 else kwargs.get('ad_payload', b"")
                handle = args[0] if len(args) > 0 else kwargs.get('handle', 0x01)
                if handle != 0x00:
                    backend._current_msg_type_name = "Message Pack"
            backend._last_ad_payload = payload
        except Exception:
            pass
        return res
    backend._set_advertising_data = patched_set_adv_data

    orig_set_adv_enable = backend._set_advertising_enable
    def patched_set_adv_enable(*args, **kwargs):
        t0 = time.monotonic()
        ts_before = time.time()
        res = orig_set_adv_enable(*args, **kwargs)
        t_inj = time.monotonic() - t0
        backend.inject_times.append(t_inj)

        enable = args[0] if len(args) > 0 else kwargs.get('enable', False)
        if enable and hasattr(backend, '_current_drone_mac') and backend._current_drone_mac:
            ts_now = ts_before
            payload = getattr(backend, '_last_ad_payload', b"")
            mac_upper = backend._current_drone_mac.upper()
            mtype = getattr(backend, '_current_msg_type_name', "Unknown")
            cyc = getattr(backend, 'current_cycle', 0)
            with backend.lock:
                if mac_upper not in backend.packets_transmitted:
                    backend.packets_transmitted[mac_upper] = []
                backend.packets_transmitted[mac_upper].append(ts_now)
                backend.tx_records.append((cyc, ts_now, mac_upper, mtype))
                backend.buffered_tx_packets.append({
                    "timestamp": ts_now,
                    "mac": mac_upper,
                    "raw_ad": payload
                })
        return res
    backend._set_advertising_enable = patched_set_adv_enable

    orig_transmit_loop = backend._transmit_loop
    def patched_transmit_loop():
        while backend._running:
            if not backend._sock:
                time.sleep(0.1)
                continue
            active_drones = [d for d in backend._drones if getattr(d, 'active', True)]
            if not active_drones:
                time.sleep(0.1)
                continue

            t_loop_start = time.monotonic()
            cycle_idx = getattr(backend, 'current_cycle', 0)
            all_sequences = []
            t_build_start = time.monotonic()
            for drone in active_drones:
                messages = backend._packet_builder(drone)
                drone_key = drone.serial
                send_sequence = backend._build_send_sequence(drone_key, messages)
                all_sequences.append((drone, messages, send_sequence))
            t_build = time.monotonic() - t_build_start
            backend.build_times.append(t_build)

            is_extended = isinstance(backend, BleExtendedBackend)
            mode = getattr(backend, 'mode', 'extended' if getattr(backend, 'pure_bt5', False) else 'dual') if is_extended else 'legacy'

            if is_extended and mode in ("ext-legacy", "dual"):
                current_legacy_interval_ms = backend.legacy_interval_ms
                dynamic_legacy_dwell = backend.legacy_interval_ms / 1000.0
            else:
                current_legacy_interval_ms = getattr(backend, 'legacy_interval_ms', getattr(backend, 'advertising_interval_ms', 100))
                dynamic_legacy_dwell = current_legacy_interval_ms / 1000.0

            for item in all_sequences:
                if not backend._running:
                    break
                drone = item[0]
                messages = item[1]
                send_sequence = item[2]
                drone_key = drone.serial
                mac_upper = drone.ble_address.upper()
                backend._current_drone_mac = mac_upper

                if is_extended:
                    if not hasattr(backend, '_extended_counters'):
                        backend._extended_counters = {}
                    counter = backend._extended_counters.get(drone_key, 0)

                    opt_params = getattr(backend, 'optimize_params', True)
                    if mode == "ext-legacy":
                        if opt_params:
                            if not hasattr(backend, '_last_configured_legacy_interval') or backend._last_configured_legacy_interval != current_legacy_interval_ms:
                                backend._set_advertising_enable(False, [0x00])
                                backend._set_advertising_params(0x00, 0x0010, 0x01, 0x01, 0x00, interval_ms=current_legacy_interval_ms)
                                backend._last_configured_legacy_interval = current_legacy_interval_ms
                            backend._set_random_address(0x00, drone.ble_address)
                        else:
                            backend._set_advertising_enable(False, [0x00])
                            backend._set_advertising_params(0x00, 0x0010, 0x01, 0x01, 0x00, interval_ms=current_legacy_interval_ms)
                            backend._set_random_address(0x00, drone.ble_address)

                        for msg in send_sequence:
                            if not backend._running:
                                break
                            mtype = get_msg_type_name(msg)
                            backend._current_msg_type_name = mtype
                            legacy_ad = backend._build_legacy_ad(msg, counter)
                            backend._set_advertising_data(0x00, legacy_ad)
                            with backend.lock:
                                backend.expected_records.append((cycle_idx, time.time(), mac_upper, mtype))
                            backend._set_advertising_enable(True, [0x00])
                            time.sleep(dynamic_legacy_dwell)
                            backend._set_advertising_enable(False, [0x00])
                            counter = (counter + 1) & 0xFF

                    elif mode == "extended":
                        # Pure BT5: Extended Message Pack on Handle 1 (Coded PHY)
                        if not opt_params:
                            backend._set_advertising_enable(False, [0x01])
                            backend._set_advertising_params(0x01, 0x0000, 0x03, 0x03, 0x01, interval_ms=backend.advertising_interval_ms)
                        backend._set_random_address(0x01, drone.ble_address)
                        pack_ad = backend._build_message_pack_ad(messages, counter)
                        backend._set_advertising_data(0x01, pack_ad)
                        backend._flush_adv_terminated_events(0x01)
                        with backend.lock:
                            backend.expected_records.append((cycle_idx, time.time(), mac_upper, "Message Pack"))
                        backend._set_advertising_enable(True, [0x01], max_events=1)
                        timeout_s = max(0.2, (backend.advertising_interval_ms / 1000.0) * 1.5)
                        backend._wait_for_adv_terminated(0x01, timeout=timeout_s)
                        counter = (counter + 1) & 0xFF

                    else:  # dual mode
                        if opt_params:
                            if not hasattr(backend, '_last_configured_legacy_interval') or backend._last_configured_legacy_interval != current_legacy_interval_ms:
                                backend._set_advertising_enable(False, [0x00])
                                backend._set_advertising_params(0x00, 0x0010, 0x01, 0x01, 0x00, interval_ms=current_legacy_interval_ms)
                                backend._last_configured_legacy_interval = current_legacy_interval_ms
                            backend._set_random_address(0x00, drone.ble_address)
                            backend._set_random_address(0x01, drone.ble_address)
                        else:
                            backend._set_advertising_enable(False, [0x00, 0x01])
                            backend._set_advertising_params(0x00, 0x0010, 0x01, 0x01, 0x00, interval_ms=current_legacy_interval_ms)
                            backend._set_random_address(0x00, drone.ble_address)
                            backend._set_advertising_params(0x01, 0x0000, 0x03, 0x03, 0x01, interval_ms=backend.advertising_interval_ms)
                            backend._set_random_address(0x01, drone.ble_address)

                        pack_ad = backend._build_message_pack_ad(messages, counter)
                        backend._set_advertising_data(0x01, pack_ad)
                        with backend.lock:
                            backend.expected_records.append((cycle_idx, time.time(), mac_upper, "Message Pack"))
                        backend._set_advertising_enable(True, [0x01])
                        for msg in send_sequence:
                            if not backend._running:
                                break
                            mtype = get_msg_type_name(msg)
                            backend._current_msg_type_name = mtype
                            legacy_ad = backend._build_legacy_ad(msg, counter)
                            backend._set_advertising_data(0x00, legacy_ad)
                            with backend.lock:
                                backend.expected_records.append((cycle_idx, time.time(), mac_upper, mtype))
                            backend._set_advertising_enable(True, [0x00])
                            time.sleep(dynamic_legacy_dwell)
                            backend._set_advertising_enable(False, [0x00])
                            counter = (counter + 1) & 0xFF
                        backend._set_advertising_enable(False, [0x01])

                    backend._extended_counters[drone_key] = counter

                else:
                    if not hasattr(backend, '_legacy_counters'):
                        backend._legacy_counters = {}
                    counter = backend._legacy_counters.get(drone_key, 0)
                    backend._set_advertising_enable(False)
                    backend._set_random_address(drone.ble_address)

                    dwell_time = backend.advertising_interval_ms / 1000.0
                    current_interval_ms = backend.advertising_interval_ms
                    backend._set_advertising_params(current_interval_ms)

                    for msg in send_sequence:
                        if not backend._running:
                            break
                        mtype = get_msg_type_name(msg)
                        backend._current_msg_type_name = mtype
                        backend._set_advertising_data(msg, counter)
                        with backend.lock:
                            backend.expected_records.append((cycle_idx, time.time(), mac_upper, mtype))
                        backend._set_advertising_enable(True)
                        time.sleep(dwell_time)
                        backend._set_advertising_enable(False)
                        counter = (counter + 1) & 0xFF
                    backend._legacy_counters[drone_key] = counter

            t_loop = time.monotonic() - t_loop_start
            backend.loop_times.append(t_loop)
            if t_loop > 1.0:
                backend.missed_deadlines += 1
            else:
                time.sleep(1.0 - t_loop)
            backend.current_cycle = getattr(backend, 'current_cycle', 0) + 1
            if getattr(backend, 'max_cycles', None) is not None and backend.current_cycle >= backend.max_cycles:
                logger.info(f"Target of {backend.max_cycles} loop cycles completed ({backend.current_cycle - 2} eval + 2 buffer); stopping loop.")
                backend._running = False
                for d in getattr(backend, '_drones', []):
                    d.active = False
                break
    backend._transmit_loop = patched_transmit_loop


def run_experiment(tx_adapter: str, ble_mode: str, rx_pcap: Optional[str], nrf_port: Optional[str],
                   rx_adapter: Optional[str], num_drones: int, duration: float, interval: float,
                   ble_interval_ms: int = 200, legacy_interval_ms: Optional[int] = None,
                   extended_interval_ms: Optional[int] = None,
                   no_self_id: bool = True, no_operator_id: bool = False,
                   coded_phy: bool = False, print_live: bool = False, optimize_params: bool = True,
                   rx_mode: str = "auto"):
    
    # Map legacy transport alias if passed
    mode_map = {
        "pure_bt5": "extended", "bt5": "extended", "ble5": "extended", "extended": "extended",
        "ble4": "legacy", "legacy": "legacy",
        "ext-legacy": "ext-legacy", "ext_legacy": "ext-legacy",
        "dual": "dual"
    }
    mode = mode_map.get(ble_mode.lower(), "extended")

    args = argparse.Namespace(
        interface=tx_adapter,
        manual=False,
        random=num_drones,
        serial=None,
        interval=interval,
        location=(473763399, 85312562), # Random base location (Zurich)
        verbose=False,
        transport="ble",
        ble_mode=mode,
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

    if rx_mode == "ble5":
        coded_phy = True
        active_rx_mode = "ble5"
    elif rx_mode == "ble4":
        coded_phy = False
        active_rx_mode = "ble4"
    else:
        if mode == "extended" or coded_phy:
            coded_phy = True
            active_rx_mode = "ble5"
        else:
            coded_phy = False
            active_rx_mode = "ble4"

    logger.info(f"=== Starting BLE Experiment: Drones={num_drones}, Mode={mode} (RX Sniffer: {active_rx_mode.upper()}), Interval={ble_interval_ms}ms, Target Cycles={target_cycles} ===")

    # Initialize Sniffer Subprocess Thread
    rx_sniffer = None
    if nrf_port or rx_pcap:
        sniffer_ble_mode = "extended" if coded_phy else "legacy"
        rx_sniffer = NrfSnifferThread(nrf_port=nrf_port, rx_pcap=rx_pcap, coded=coded_phy, print_live=print_live, ble_mode=sniffer_ble_mode)
        rx_sniffer.start()
        time.sleep(1.0)
        wait_for_sniffer_ready(2, "Waiting 2s for nRF sniffer radio to initialize and stabilize on channel...")

    leg_ival = legacy_interval_ms if legacy_interval_ms is not None else ble_interval_ms
    ext_ival = extended_interval_ms if extended_interval_ms is not None else (20 if mode == "dual" else ble_interval_ms)

    # Initialize Backend
    if mode == "legacy":
        backend = BleLegacyBackend(adapter=tx_adapter, advertising_interval_ms=leg_ival)
    else:
        backend = BleExtendedBackend(adapter=tx_adapter, legacy_interval_ms=leg_ival, extended_interval_ms=ext_ival, mode=mode, optimize_params=optimize_params)

    instrument_backend(backend, max_cycles=target_cycles)
    spoofer = DroneSpoofer(args, [backend])
    t_start = time.time()
    try:
        spoofer.run_automatic_mode()
    finally:
        backend.close()
    t_end = time.time()

    # Dynamically wait for lingering over-the-air packets and UART PCAP pipe buffer to drain
    if rx_sniffer:
        logger.info("Waiting for nRF sniffer serial stream buffer to drain...")
        settled_start = time.time()
        last_count = -1
        while time.time() - settled_start < 6.0:
            with rx_sniffer.lock:
                current_count = len(rx_sniffer.raw_records)
            if current_count != last_count:
                last_count = current_count
                settled_start = time.time()  # reset timer when packets are actively streaming in
            time.sleep(0.5)
            if time.time() - settled_start >= 2.0 and current_count > 0:
                # 2 seconds of silence on the stream indicates all trailing packets have drained
                break
        rx_sniffer.stop()
        rx_sniffer.join(timeout=3.0)

    # Analysis & MAC Correlation using strict Cycle Indexing (preventing bucket jumping on missed deadlines)
    num_buckets = int(round(duration / interval))
    
    mac_to_serial: Dict[str, str] = getattr(backend, 'registered_drones', {})

    # Strictly select expected records and tx transmissions belonging to our target evaluation cycles (0 to num_buckets - 1)
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

    # Filter HCI transmissions to target evaluation cycles
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

    # Correlation, Payload Verification, and Comprehensive Evaluation Statistics
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

    drone_payload_counts: Dict[str, Dict[str, int]] = {
        mac: {"basic_id": 0, "location": 0, "system": 0, "operator_id": 0, "complete_packs": 0, "total_rx": 0}
        for mac in mac_to_serial.keys()
    }
    
    total_complete_packs = 0
    matched_rx_by_mac: Dict[str, List[float]] = {mac: [] for mac in mac_to_serial.keys()}
    propagation_latencies_ms = []

    if rx_sniffer:
        with rx_sniffer.lock:
            sorted_records = sorted(rx_sniffer.raw_records, key=lambda x: x.get("timestamp", 0))
            for rec in sorted_records:
                mac = rec.get("mac", "").upper()
                if mac not in tx_items_by_mac:
                    continue
                ts_rx = rec.get("timestamp", 0)

                rx_types = []
                rid = rec.get("remote_id")
                if rid and isinstance(rid, dict):
                    msgs = rid.get("parsed_messages", [])
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

                    rid = rec.get("remote_id")
                    if rid and isinstance(rid, dict):
                        msgs = rid.get("parsed_messages", [])
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
            iats = [(times[i] - times[i - 1]) * 1000.0 for i in range(1, count)]
            all_iats_ms.extend(iats)
            for i in range(1, len(iats)):
                jitter_list.append(abs(iats[i] - iats[i - 1]))

    avg_jitter = statistics.mean(jitter_list) / 1000.0 if jitter_list else 0.0
    pdr_tx = (total_tx_received / expected_total_packets * 100.0) if expected_total_packets > 0 else 0.0
    pdr_rx = (total_rx_received / expected_total_packets * 100.0) if expected_total_packets > 0 else 0.0

    complete_pack_ratio = (total_complete_packs / expected_total_packets * 100.0) if expected_total_packets > 0 else 0.0
    drones_with_rx = sum(1 for mac, counts in drone_payload_counts.items() if counts["total_rx"] > 0 or len(matched_rx_by_mac.get(mac, [])) > 0)

    per_drone_stats = []
    for mac, serial in mac_to_serial.items():
        exp = expected_by_mac.get(mac, 0)
        sent = len(filtered_tx.get(mac, []))
        sniffed = len(matched_rx_by_mac.get(mac, []))
        counts = drone_payload_counts.get(mac, {})
        pdr = (sniffed / exp * 100.0) if exp > 0 else 0.0
        per_drone_stats.append({
            "serial": serial,
            "mac": mac,
            "expected": exp,
            "tx_sent": sent,
            "rx_sniffed": sniffed,
            "pdr_percent": pdr,
            "basic_id_count": counts.get("basic_id", 0),
            "location_count": counts.get("location", 0),
            "system_count": counts.get("system", 0),
            "operator_id_count": counts.get("operator_id", 0),
            "complete_packs": counts.get("complete_packs", 0)
        })

    build_stats = get_percentiles([t * 1000 for t in getattr(backend, 'build_times', [])])
    inject_stats = get_percentiles([t * 1000 for t in getattr(backend, 'inject_times', [])])
    loop_stats = get_percentiles([t * 1000 for t in getattr(backend, 'loop_times', [])])
    iat_stats = get_percentiles(all_iats_ms)
    propagation_stats = get_percentiles(propagation_latencies_ms)

    actual_duration = t_end - t_start

    logger.info(f"=== Results Summary ({num_drones} Drones, Mode={mode}) ===")
    logger.info(f"PDR: TX Sent {total_tx_received}/{expected_total_packets} ({pdr_tx:.2f}%) | RX Sniffed {total_rx_received}/{expected_total_packets} ({pdr_rx:.2f}%)")
    logger.info(f"Drones Active with RX: {drones_with_rx}/{num_drones} | Complete RID Packs: {total_complete_packs}/{expected_total_packets} ({complete_pack_ratio:.2f}%)")
    logger.info(f"Latency Avg: {propagation_stats['avg']:.2f}ms (p95={propagation_stats['p95']:.2f}ms) | Jitter Avg: {avg_jitter*1000:.2f}ms")
    logger.info(f"Execution Times: Build Avg={build_stats['avg']:.2f}ms | Inject Avg={inject_stats['avg']:.2f}ms (p95={inject_stats['p95']:.2f}ms) | Loop Avg={loop_stats['avg']:.2f}ms")
    logger.info(f"Missed Deadlines: {backend.missed_deadlines}")

    return {
        "drones": num_drones,
        "duration": duration,
        "interval": interval,
        "ble_mode": mode,
        "rx_mode": active_rx_mode,
        "transport": mode,
        "tx_adapter": tx_adapter,
        "ble_interval_ms": ble_interval_ms,
        "legacy_interval_ms": leg_ival,
        "extended_interval_ms": ext_ival,
        "expected_packets": expected_total_packets,
        "tx_received_packets": total_tx_received,
        "rx_received_packets": total_rx_received,
        "drones_with_rx": drones_with_rx,
        "pdr_tx_percent": pdr_tx,
        "pdr_rx_percent": pdr_rx,
        "complete_pack_ratio_percent": complete_pack_ratio,
        "total_complete_packs": total_complete_packs,
        "avg_jitter_ms": avg_jitter * 1000,
        "avg_inject_time_ms": inject_stats["avg"],
        "max_inject_time_ms": inject_stats["max"],
        "avg_build_time_ms": build_stats["avg"],
        "avg_loop_time_ms": loop_stats["avg"],
        "iat_stats_ms": iat_stats,
        "propagation_latency_stats_ms": propagation_stats,
        "inject_time_stats_ms": inject_stats,
        "build_time_stats_ms": build_stats,
        "loop_time_stats_ms": loop_stats,
        "per_drone_stats": per_drone_stats,
        "msg_type_stats": msg_type_stats,
        "inject_times_ms": [t * 1000 for t in backend.inject_times] if hasattr(backend, 'inject_times') else [],
        "per_second_stats": {
            "expected": expected_buckets,
            "tx_sniffed": tx_buckets,
            "rx_sniffed": rx_buckets
        },
        "performance": {
            "missed_deadlines": backend.missed_deadlines,
            "actual_duration": actual_duration,
            "requested_duration": duration
        },
        "raw_data": {
            "t_start_unix": t_start,
            "tx_timestamps": backend.packets_transmitted,
            "rx_timestamps": matched_rx_by_mac,
            "propagation_latencies_ms": propagation_latencies_ms,
            "iats_ms": all_iats_ms,
            "build_times_ms": [t * 1000 for t in backend.build_times] if hasattr(backend, 'build_times') else [],
            "inject_times_ms": [t * 1000 for t in backend.inject_times] if hasattr(backend, 'inject_times') else [],
            "loop_times_ms": [t * 1000 for t in backend.loop_times] if hasattr(backend, 'loop_times') else []
        }
    }


def parse_drones_spec(spec: str) -> List[int]:
    """
    Parse a flexible drone count specification string.
    Supports:
      - Comma separated list: "10,20,50,100"
      - Range with step: "5-100:5" (5 to 100 in steps of 5)
      - Mixed formats: "5, 10, 15-50:5, 60-100:10"
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
    parser = argparse.ArgumentParser(description="Evaluate Bluetooth (BLE) Capacity")
    parser.add_argument("--tx-adapter", default="hci0", help="Transmit Bluetooth HCI adapter (default: hci0)")
    parser.add_argument("--ble-mode", choices=["extended", "ext-legacy", "ext_legacy", "legacy", "dual"], default="extended", help="BLE transmission mode: 'extended' (default), 'ext-legacy', 'legacy', or 'dual'")
    parser.add_argument("--transport", default=None, choices=["ble4", "legacy", "ble5", "extended", "pure_bt5", "bt5", "ext-legacy", "dual"], help="Legacy transport alias for --ble-mode")
    parser.add_argument("--optimize-params", action="store_true", default=True, help="Omit redundant HCI parameter re-configuration on each drone pulse (default: True)")
    parser.add_argument("--no-optimize-params", "--reconfigure-params", action="store_false", dest="optimize_params", help="Force per-drone HCI parameter re-application on every pulse")
    parser.add_argument("--rx-pcap", help="Path to PCAP file or FIFO pipe for nRF sniffer")
    parser.add_argument("--nrf-port", help="Serial port for nRF sniffer (e.g. /dev/ttyACM0). Automatically runs nrfutil ble-sniffer via nrf_bt_sniffer_json")
    parser.add_argument("--rx-adapter", help="Optional secondary HCI adapter for raw RX sniffing (e.g. hci1)")
    parser.add_argument("--drones", type=str, default="5,10,15,20,25,30,35,40,45,50", help="Comma separated list or range (e.g. 1-40:1) of drone counts to sweep")
    parser.add_argument("--consecutive-misses", type=int, default=2, help="Terminate sweep early when 100%% of deadlines are missed for N consecutive drone counts (default: 2; 0 to disable)")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration per test in seconds")
    parser.add_argument("--interval", type=float, default=1.0, help="Main spoofer update interval in seconds")
    parser.add_argument("--ble-interval-ms", type=int, default=200, help="Default BLE advertising interval in ms")
    parser.add_argument("--legacy-interval-ms", type=int, default=None, help="BLE 4 legacy advertising interval in ms (overrides --ble-interval-ms for legacy/dual)")
    parser.add_argument("--extended-interval-ms", type=int, default=None, help="BLE 5 extended advertising interval in ms (overrides --ble-interval-ms for extended/dual)")
    parser.add_argument("--rx-mode", choices=["auto", "ble4", "ble5"], default="auto", help="Sniffer capture mode: 'ble5' (Coded PHY), 'ble4' (1M Legacy), or 'auto'")
    parser.add_argument("--coded", action="store_true", help="Force nRF sniffer to scan and follow LE Coded PHY")
    parser.add_argument("--with-self-id", action="store_false", dest="no_self_id", default=True, help="Enable Self ID message (disabled by default)")
    parser.add_argument("--no-operator-id", action="store_true", help="Disable Operator ID message")
    parser.add_argument("--debug-sniff", "--print-packets", action="store_true", help="Continuously print received packets in real-time JSON format")
    default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "ble_capacity_results.json")
    parser.add_argument("--out", type=str, default=default_out, help="Output JSON file (default: evaluation/data/ble_capacity_results.json)")
    parser.add_argument("--append", action="store_true", help="Append/merge new runs into existing output JSON file if it exists")
    
    args = parser.parse_args()
    mode = args.transport if args.transport is not None else args.ble_mode
    drone_counts = parse_drones_spec(args.drones)

    # Ensure output folder exists
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Auto-detect nRF sniffer device if not explicitly provided
    if args.nrf_port is None and args.rx_adapter is None and args.rx_pcap is None:
        for candidate in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"]:
            if os.path.exists(candidate):
                args.nrf_port = candidate
                logger.info(f"Auto-detected nRF BLE sniffer hardware on {candidate}")
                break
    results = []
    consecutive_full_misses = 0
    target_cycles = int(round(args.duration / args.interval))

    def flush_results_to_disk():
        out_payload = results
        if args.append and os.path.exists(args.out):
            try:
                with open(args.out, 'r') as f:
                    existing_data = json.load(f)
                if isinstance(existing_data, list):
                    merged_list = list(existing_data)
                    for res in results:
                        matched_idx = -1
                        for idx_item, item in enumerate(merged_list):
                            if (item.get("drones") == res.get("drones") and 
                                item.get("ble_mode", item.get("transport")) == res.get("ble_mode", res.get("transport")) and 
                                item.get("ble_interval_ms") == res.get("ble_interval_ms") and
                                item.get("rx_mode") == res.get("rx_mode")):
                                matched_idx = idx_item
                                break
                        if matched_idx >= 0:
                            merged_list[matched_idx] = res
                        else:
                            merged_list.append(res)
                    out_payload = merged_list
            except Exception as e:
                out_payload = results

        tmp_out = args.out + ".tmp"
        try:
            with open(tmp_out, 'w') as f:
                json.dump(out_payload, f, indent=4)
            os.replace(tmp_out, args.out)
        except Exception:
            with open(args.out, 'w') as f:
                json.dump(out_payload, f, indent=4)

    interrupted = False
    try:
        for idx, count in enumerate(drone_counts):
            res = run_experiment(
                tx_adapter=args.tx_adapter,
                ble_mode=mode,
                rx_pcap=args.rx_pcap,
                nrf_port=args.nrf_port,
                rx_adapter=args.rx_adapter,
                num_drones=count,
                duration=args.duration,
                interval=args.interval,
                ble_interval_ms=args.ble_interval_ms,
                legacy_interval_ms=args.legacy_interval_ms,
                extended_interval_ms=args.extended_interval_ms,
                no_self_id=args.no_self_id,
                no_operator_id=args.no_operator_id,
                coded_phy=args.coded,
                print_live=args.debug_sniff,
                optimize_params=args.optimize_params,
                rx_mode=args.rx_mode
            )
            results.append(res)
            flush_results_to_disk()

            missed = res.get("performance", {}).get("missed_deadlines", 0)
            if missed >= target_cycles:
                consecutive_full_misses += 1
                logger.warning(f"BLE {count} drones: 100% of deadlines missed ({missed}/{target_cycles} cycles). Consecutive full-miss runs: {consecutive_full_misses}/{args.consecutive_misses}")
            else:
                if consecutive_full_misses > 0:
                    logger.info(f"BLE {count} drones completed within deadlines ({missed}/{target_cycles} missed). Resetting consecutive miss counter.")
                consecutive_full_misses = 0

            if args.consecutive_misses > 0 and consecutive_full_misses >= args.consecutive_misses:
                logger.warning(f"Auto-terminating BLE sweep early at {count} drones: {args.consecutive_misses} consecutive runs missed 100% of deadlines. BLE capacity ceiling reached!")
                break

            if idx < len(drone_counts) - 1:
                logger.info("Cooldown before next experiment...")
                time.sleep(5.0)
    except KeyboardInterrupt:
        logger.warning("\n[!] Sweep interrupted by user. Saving collected progress so far...")
        interrupted = True
        flush_results_to_disk()

    flush_results_to_disk()
    logger.info(f"Saved BLE capacity results to {args.out}")

    # Print Summary Table
    print("\n" + "="*130)
    print(f"{'Drones':<10} | {'Expected':<10} | {'TX Sent':<12} | {'RX Sniffed':<12} | {'Jitter(ms)':<12} | {'Build(ms)':<10} | {'Inject(ms)':<10} | {'Loop(ms)':<10} | {'Missed':<8}")
    print("-" * 130)
    for r in results:
        print(f"{r['drones']:<10} | {r['expected_packets']:<10} | {r['tx_received_packets']:<12} | {r['rx_received_packets']:<12} | {r['avg_jitter_ms']:<12.2f} | {r.get('avg_build_time_ms', 0):<10.2f} | {r['avg_inject_time_ms']:<10.2f} | {r.get('avg_loop_time_ms', 0):<10.2f} | {r.get('missed_deadlines', 0):<8}")
    
    # Print Per-Drone Payload Breakdown
    for r in results:
        print(f"\n--- Per-Drone Remote ID Payload Breakdown ({r['drones']} Drones) ---")
        print(f"{'Drone Serial':<25} | {'MAC Address':<18} | {'Expected':<10} | {'TX (HCI)':<10} | {'RX (Air)':<10} | {'PDR (Air)':<10} | {'Loc(RX)':<9} | {'BasicID(RX)':<11} | {'Complete RID':<12}")
        print("-" * 125)
        for d in r.get("per_drone_stats", []):
            print(f"{d['serial']:<25} | {d['mac']:<18} | {d['expected']:<10} | {d['tx_sent']:<10} | {d['rx_sniffed']:<10} | {d['pdr_percent']:<9.2f}% | {d.get('location_count',0):<9} | {d.get('basic_id_count',0):<11} | {d.get('complete_packs', 0):<12}")
            
        print(f"\n--- ASTM Message Type Delivery Statistics ({r['drones']} Drones) ---")
        print(f"{'Message Type':<18} | {'Expected':<12} | {'TX Sent (HCI)':<15} | {'RX Sniffed (Air)':<18} | {'Delivery Rate (Air)':<18}")
        print("-" * 90)
        for mtype, stats in r.get("msg_type_stats", {}).items():
            exp = stats["expected"]
            rx_sniffed = stats["rx_sniffed"]
            rate_str = f"{(rx_sniffed / exp * 100):.2f}%" if exp > 0 else "-"
            print(f"{mtype:<18} | {exp:<12} | {stats['tx_sent']:<15} | {rx_sniffed:<18} | {rate_str:<18}")

    # Print Per-Second Breakdowns
    for r in results:
        print(f"\n--- Per-Second Breakdown for {r['drones']} Drones ---")
        print(f"{'Second':<8} | {'Expected':<10} | {'TX Sent':<12} | {'RX Sniffed':<12} | {'Dropped (HCI)':<15} | {'Dropped (Air)':<15}")
        print("-" * 80)
        
        expected = r["per_second_stats"]["expected"]
        tx = r["per_second_stats"]["tx_sniffed"]
        rx = r["per_second_stats"]["rx_sniffed"]
        
        for i in range(len(expected)):
            if expected[i] == 0 and tx[i] == 0 and rx[i] == 0:
                continue
            drop_hci = expected[i] - tx[i] if expected[i] > 0 else 0
            drop_air = tx[i] - rx[i]
            print(f"t={i:<6} | {expected[i]:<10} | {tx[i]:<12} | {rx[i]:<12} | {drop_hci:<15} | {drop_air:<15}")
    print("="*95 + "\n")

    # Generate Plot
    try:
        import matplotlib.pyplot as plt
        plt.figure(figsize=(10, 6))
        has_data = False
        for r in results:
            drones = r["drones"]
            times = r.get("inject_times_ms", [])
            if times:
                plt.plot(times, marker='o', label=f"{drones} Drones")
                has_data = True
                
        if has_data:
            plt.xlabel("Packet Index")
            plt.ylabel("HCI Injection Time (ms)")
            plt.title("BLE HCI Injection Execution Time per Packet")
            plt.legend()
            plt.grid(True)
            
            plot_file = args.out.replace(".json", "_plot.png")
            if not plot_file.endswith(".png"):
                plot_file += "_plot.png"
            plt.savefig(plot_file)
            logger.info(f"Saved BLE execution time plot to {plot_file}")
    except ImportError:
        logger.warning("matplotlib not installed. Skipping plot generation. Time series data is saved in JSON.")


if __name__ == "__main__":
    main()
