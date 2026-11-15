#!/usr/bin/env python3
"""
Quick dual-sniffer reception comparison for BLE Remote ID.

Transmits a small swarm of spoofed drones and simultaneously captures the
over-the-air advertisements with two independent receivers:

  * the nRF52840 sniffer dongle (via nrf_bt_sniffer_json.py), and
  * a Linux HCI adapter running an LE scan (raw AF_BLUETOOTH socket).

It runs two rounds back to back -- round 1 in BT5 (extended / Coded PHY) and
round 2 in BT4 (legacy) -- and prints a side-by-side reception-rate comparison
so the two receivers can be judged against the exact same transmissions.

Three radios are involved:
  --tx-adapter   HCI adapter that advertises the drones   (e.g. hci0)
  --rx-adapter   HCI adapter that scans / receives         (e.g. hci1)
  --nrf-port     serial port of the nRF sniffer dongle     (e.g. /dev/ttyACM0)

Run with sudo and the project venv, e.g.
  sudo .venv/bin/python evaluation/compare_sniffers.py --tx-adapter hci0 \
       --rx-adapter hci1 --nrf-port /dev/ttyACM0 --drones 5 --duration 20
"""

import argparse
import json
import logging
import os
import select
import socket
import statistics
import struct
import sys
import threading
import time
from typing import Any, Dict, List, Optional

# Import the shared spoofer stack and the existing nRF sniffer driver.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from drone_rid_spoofer.helpers import random_location  # noqa: E402
from drone_rid_spoofer.parser import extract_ble_rid_payload  # noqa: E402
from drone_rid_spoofer.spoofer import DroneSpoofer  # noqa: E402
from drone_rid_spoofer.transport.ble import BleExtendedBackend  # noqa: E402
from evaluation.ble_capacity import (  # noqa: E402
    NrfSnifferThread,
    instrument_backend,
    wait_for_sniffer_ready,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("compare_sniffers")

SOL_HCI = 0
HCI_FILTER = 2

# HCI opcodes for scanning.
OCF_LE_SET_EXT_SCAN_PARAMS = 0x2041
OCF_LE_SET_EXT_SCAN_ENABLE = 0x2042

# Scanning_PHYs bitfield for HCI_LE_Set_Extended_Scan_Parameters. An LE 1M scan also receives
# legacy advertising, so ext-legacy (legacy PDUs on 1M) scans 1M and BT5 extended scans Coded.
HCI_SCAN_PHY_1M = 0x01
HCI_SCAN_PHY_CODED = 0x04
HCI_SCAN_PHY_NAMES = {HCI_SCAN_PHY_1M: "LE 1M PHY", HCI_SCAN_PHY_CODED: "LE Coded PHY"}
# Scan interval = window per PHY, in 0.625 ms units: 0x0640 = 1 s. The RID_Scanner project
# measured that short windows (10 ms) capture *no* LE Coded at all while ~1 s windows capture
# Coded as well as a Coded-only scan, so a full-second window is required for BT5 reception.
HCI_EXT_SCAN_WINDOW = 0x0640

# Base location for the random swarm (Zurich), matching ble_capacity.py.
BASE_LOCATION = (473763399, 85312562)


def _addr_le_to_str(addr: bytes) -> str:
    """Convert a little-endian 6-byte BLE address into an upper-case MAC string."""
    return ":".join(f"{b:02X}" for b in reversed(addr))


def _basic_id_serial(parsed_messages: List[Dict[str, Any]]) -> Optional[str]:
    """Return the UAS serial carried by a Basic ID message, if one is present.

    Used to verify frame contents: a frame whose decoded serial does not match the
    serial we transmitted for that MAC is a corrupted (or foreign) frame, even if it
    parsed structurally. Returns None when no Basic ID message is in the payload.
    """
    for m in parsed_messages:
        if isinstance(m, dict) and m.get("type") == "Basic ID":
            sid = m.get("id")
            if sid is None:
                return None
            return sid.decode("utf-8", "replace").rstrip("\x00") if isinstance(sid, bytes) else str(sid)
    return None


class HciRidSniffer(threading.Thread):
    """Capture Remote ID advertisements on an HCI adapter via a raw LE scan.

    Records one reception timestamp per MAC for every advertisement that carries
    a valid ASTM F3411 Remote ID payload, so its coverage can be compared against
    the nRF sniffer on identical transmissions.
    """

    def __init__(self, adapter: str = "hci1", scan_phys: int = HCI_SCAN_PHY_CODED,
                 print_live: bool = False):
        super().__init__(daemon=True)
        self.adapter = adapter
        self.dev_id = int(adapter.replace("hci", "")) if adapter.startswith("hci") else 0
        self.scan_phys = scan_phys
        self.phy_name = HCI_SCAN_PHY_NAMES.get(scan_phys, f"0x{scan_phys:02X}")
        self.print_live = print_live
        self.running = False
        self.ready = False
        self.error: Optional[str] = None
        self.sock: Optional[socket.socket] = None
        # mac -> list of (timestamp, types, crc_ok, basic_id_serial) per RID advertisement.
        self.records: Dict[str, List[tuple]] = {}
        self.lock = threading.Lock()

    @staticmethod
    def _hci_cmd(opcode: int, data: bytes) -> bytes:
        return struct.pack("<BHB", 0x01, opcode, len(data)) + data

    def _open(self) -> bool:
        try:
            self.sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
            self.sock.bind((self.dev_id,))
        except Exception as e:  # pragma: no cover - hardware dependent
            self.error = f"failed to open HCI socket on {self.adapter}: {e}"
            logger.error(self.error)
            return False

        # Receive HCI event packets (LE Meta Events carry advertising reports).
        type_mask = 1 << 4  # HCI_EVENT_PKT
        filter_bytes = struct.pack("<IIIH", type_mask, 0xFFFFFFFF, 0xFFFFFFFF, 0) + b"\x00\x00"
        self.sock.setsockopt(SOL_HCI, HCI_FILTER, filter_bytes)

        try:
            # Make sure any previous extended scan is stopped first.
            self.sock.send(self._hci_cmd(OCF_LE_SET_EXT_SCAN_ENABLE, struct.pack("<BB", 0x00, 0x00)))

            # Always use the extended-scan commands (the Core Spec forbids mixing legacy and
            # extended scanning, and only an extended scan can receive LE Coded PHY). The round
            # selects the PHY via self.scan_phys: Coded for BT5, 1M for ext-legacy. A 1M scan
            # also reports legacy advertising. Per-PHY tuple: Scan_Type passive(0x00),
            # Interval, Window -- repeated once per set PHY bit.
            phy_count = bin(self.scan_phys).count("1")
            own_addr_type = 0x01  # Random; retried as Public below if rejected
            per_phy = struct.pack("<BHH", 0x00, HCI_EXT_SCAN_WINDOW, HCI_EXT_SCAN_WINDOW)
            params = struct.pack("<BBB", own_addr_type, 0x00, self.scan_phys) + per_phy * phy_count
            self.sock.send(self._hci_cmd(OCF_LE_SET_EXT_SCAN_PARAMS, params))
            # Blind retry with Public address (0x00) in case Random was rejected.
            self.sock.send(self._hci_cmd(OCF_LE_SET_EXT_SCAN_PARAMS, bytes([0x00]) + params[1:]))
            # Enable, filter_duplicates=0x00 so every advertisement is reported.
            self.sock.send(self._hci_cmd(OCF_LE_SET_EXT_SCAN_ENABLE,
                                         struct.pack("<BBHH", 0x01, 0x00, 0x0000, 0x0000)))
        except OSError as e:
            self.error = (f"adapter {self.adapter} rejected {self.phy_name} extended scan "
                          f"(a BT5 adapter is required to scan LE Coded PHY): {e}")
            logger.error(self.error)
            self.sock.close()
            self.sock = None
            return False
        return True

    def run(self) -> None:
        self.running = True
        if not self._open():
            self.running = False
            return
        self.ready = True
        logger.info("HCI sniffer scanning on %s (%s, 1 s window)", self.adapter, self.phy_name)

        while self.running:
            try:
                ready, _, _ = select.select([self.sock], [], [], 0.5)
            except Exception:
                break
            if not ready:
                continue
            try:
                pkt = self.sock.recv(300)
            except OSError:
                break
            self._handle_event(pkt)

        self._close()
        self.running = False

    def _handle_event(self, pkt: bytes) -> None:
        # HCI event packet: 0x04 | event_code | param_len | params...
        if len(pkt) < 4 or pkt[0] != 0x04 or pkt[1] != 0x3E:
            return
        subevent = pkt[3]
        if subevent == 0x0D:  # LE Extended Advertising Report
            self._parse_reports(pkt, legacy=False)
        elif subevent == 0x02:  # LE Advertising Report (legacy)
            self._parse_reports(pkt, legacy=True)

    def _parse_reports(self, pkt: bytes, legacy: bool) -> None:
        num_reports = pkt[4]
        offset = 5
        for _ in range(num_reports):
            try:
                if legacy:
                    # event_type(1) addr_type(1) addr(6) data_len(1) data[..] rssi(1)
                    if offset + 9 > len(pkt):
                        break
                    _, _, addr, d_len = struct.unpack("<BB6sB", pkt[offset:offset + 9])
                    data = pkt[offset + 9:offset + 9 + d_len]
                    offset += 9 + d_len + 1  # trailing RSSI byte
                else:
                    # 24-byte fixed header (incl. rssi) then data[data_len]; no trailing byte.
                    if offset + 24 > len(pkt):
                        break
                    fields = struct.unpack("<HB6sBBBbbHB6sB", pkt[offset:offset + 24])
                    addr = fields[2]
                    d_len = fields[11]
                    data = pkt[offset + 24:offset + 24 + d_len]
                    offset += 24 + d_len
            except struct.error:
                break
            self._maybe_record(addr, data)

    def _maybe_record(self, addr: bytes, adv_data: bytes) -> None:
        rid = extract_ble_rid_payload(adv_data)
        if rid is None:
            return
        _, _, parsed_messages, _ = rid
        types = tuple(m.get("type", "Unknown") for m in parsed_messages if isinstance(m, dict))
        basic_id = _basic_id_serial(parsed_messages)
        mac = _addr_le_to_str(addr)
        ts = time.time()
        # An HCI controller only reports PDUs that passed CRC, so crc_ok is always True here.
        with self.lock:
            self.records.setdefault(mac, []).append((ts, types, True, basic_id))
        if self.print_live:
            print(f"[HCI] {mac} RID {list(types)} @ {ts:.3f}")
            sys.stdout.flush()

    def _close(self) -> None:
        if not self.sock:
            return
        try:
            self.sock.send(self._hci_cmd(OCF_LE_SET_EXT_SCAN_ENABLE, struct.pack("<BB", 0x00, 0x00)))
        except Exception:
            pass
        try:
            self.sock.close()
        except Exception:
            pass
        self.sock = None

    def stop(self) -> None:
        self.running = False


# Correlation window around a transmission, matching ble_capacity.py: a received
# message may lag its HCI-enable timestamp by up to this many seconds (and arrive
# up to 50 ms early due to clock skew) and still be credited to that transmission.
MATCH_BACK_S = 0.05
MATCH_FWD_S = 3.0


def _match_expected(recs_by_mac: Dict[str, List[list]], expected: List[tuple],
                    macs: List[str]) -> Dict[str, int]:
    """Greedily match each expected message to one unconsumed reception by time+type.

    recs_by_mac maps a MAC to a time-sorted list of mutable [ts, types_set, consumed]
    entries; this consumes at most one per expected message. Returns per-MAC covered
    counts. Call with a fresh copy of the reception lists per pass.
    """
    cov = dict.fromkeys(macs, 0)
    for ts_tx, mac, mtype in expected:
        for rec in recs_by_mac.get(mac, ()):
            ts_rx, types, consumed = rec
            if consumed or ts_rx < ts_tx - MATCH_BACK_S:
                continue
            if ts_rx > ts_tx + MATCH_FWD_S:
                break
            # A Message Pack carries every sub-message, so any RID packet satisfies
            # it; a legacy message needs its specific type.
            if mtype == "Message Pack" or mtype in types:
                rec[2] = True
                cov[mac] += 1
                break
    return cov


def compute_reception(received: Dict[str, List[tuple]], expected_records: List[tuple],
                      macs: List[str], mac_to_serial: Dict[str, str],
                      num_buckets: int) -> Dict[str, Any]:
    """Score one receiver against the transmitter's expected-message records.

    Each received entry is (ts, types, crc_ok, basic_id_serial). A frame is counted as
    a genuine reception of one of our drones' advertisements only when it is CRC-valid
    and, if it carries a Basic ID, its serial matches the serial we transmitted for that
    MAC. This is rigorous attribution: a passing CRC guarantees the whole PDU (MAC and
    payload) is intact, and the MAC is unique to the spoofed drone. CRC-failed frames
    are NOT counted -- they cannot be attributed to our transmission without comparing
    raw bytes against ground truth -- but their count is reported as a diagnostic (it
    should be near zero at short range; a non-zero serial mismatch among CRC-valid
    frames would signal a problem and is reported too).

    PDR is the fraction of transmitted messages with such a matching reception. The
    duplication rate is the mean number of valid captured copies per transmitted
    message, which for legacy (BT4) advertising measures the 3-channel/dwell redundancy.
    """
    mac_set = set(macs)

    attributable: Dict[str, List[list]] = {m: [] for m in macs}  # for matching
    packets_by_mac = dict.fromkeys(macs, 0)
    valid_by_mac = dict.fromkeys(macs, 0)
    channel_counts: Dict[str, int] = {}   # RF channel of valid frames (nRF only)
    valid_ts_by_mac: Dict[str, List[float]] = {m: [] for m in macs}
    crc_failed = content_mismatch = 0
    for mac, recs in received.items():
        if mac not in mac_set:
            continue
        expected_serial = mac_to_serial.get(mac, "")
        for ts, types, crc_ok, serial, channel in recs:
            packets_by_mac[mac] += 1
            if crc_ok is False:
                crc_failed += 1  # diagnostic only; never counted as a reception
                continue
            # Sanity: a CRC-valid Basic ID frame must carry the serial we sent.
            if serial is not None and expected_serial and serial != expected_serial:
                content_mismatch += 1
                continue
            valid_by_mac[mac] += 1
            valid_ts_by_mac[mac].append(ts)
            ch_key = str(channel) if channel is not None else "n/a"
            channel_counts[ch_key] = channel_counts.get(ch_key, 0) + 1
            attributable[mac].append([ts, set(types), False])
    for mac in attributable:
        attributable[mac].sort(key=lambda r: r[0])

    # Inter-arrival time between successive valid captures of the same drone (ms),
    # pooled across drones -- small for BT4 (many copies per dwell), ~interval for BT5.
    iats_ms: List[float] = []
    for mac in macs:
        stamps = sorted(valid_ts_by_mac[mac])
        iats_ms.extend((stamps[i] - stamps[i - 1]) * 1000.0 for i in range(1, len(stamps)))
    median_iat_ms = statistics.median(iats_ms) if iats_ms else 0.0

    expected = sorted(
        ((ts, mac, mtype) for cyc, ts, mac, mtype, *_ in expected_records
         if mac in mac_set and 0 <= cyc < num_buckets),
        key=lambda e: e[0],
    )
    exp_by_mac = dict.fromkeys(macs, 0)
    for _ts, mac, _mtype in expected:
        exp_by_mac[mac] += 1

    cov = _match_expected(attributable, expected, macs)

    per_mac = {}
    total_expected = total_covered = total_packets = total_valid = drones_seen = 0
    for mac in macs:
        exp, c, pkts, vpkts = exp_by_mac[mac], cov[mac], packets_by_mac[mac], valid_by_mac[mac]
        total_expected += exp
        total_covered += c
        total_packets += pkts
        total_valid += vpkts
        if vpkts > 0:
            drones_seen += 1
        per_mac[mac] = {
            "expected": exp,
            "received": c,
            "valid_packets": vpkts,
            "packets": pkts,
            "pdr_percent": (c / exp * 100.0) if exp else 0.0,
            "duplication_rate": (vpkts / exp) if exp else 0.0,
        }
    return {
        "expected": total_expected,
        "received": total_covered,
        "total_packets": total_packets,
        "valid_packets": total_valid,
        "crc_failed_packets": crc_failed,
        "content_mismatch_packets": content_mismatch,
        "duplication_rate": (total_valid / total_expected) if total_expected else 0.0,
        "channel_counts": channel_counts,
        "median_iat_ms": median_iat_ms,
        "drones_seen": drones_seen,
        "pdr_percent": (total_covered / total_expected * 100.0) if total_expected else 0.0,
        "per_mac": per_mac,
    }


def run_round(mode: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Transmit the swarm in the given mode while both receivers capture."""
    norm_mode = mode.replace("_", "-")  # "extended" or "ext-legacy"
    # BT5 extended uses Coded-PHY extended PDUs; ext-legacy emits legacy 1M-PHY
    # PDUs via the extended HCI API, so the receivers scan in legacy form.
    scan_extended = (norm_mode == "extended")
    label = "BT5 (extended)" if scan_extended else "BT4 (ext-legacy)"
    num_buckets = int(round(args.duration / args.interval))
    target_cycles = num_buckets + 2
    safety = max(300.0, (args.duration + 2.0 * args.interval) * 5.0)

    logger.info("=== Round: %s | drones=%d duration=%.0fs interval=%.0fs ===",
                label, args.drones, args.duration, args.interval)

    # --- Start both receivers (both are mandatory) -----------------------------
    nrf = NrfSnifferThread(
        nrf_port=args.nrf_port,
        print_live=args.debug,
        ble_mode="extended" if scan_extended else "legacy",
        filter_channels=args.filter_channels,
    )
    nrf.start()
    time.sleep(1.0)

    hci_scan_phys = HCI_SCAN_PHY_CODED if scan_extended else HCI_SCAN_PHY_1M
    hci = HciRidSniffer(adapter=args.rx_adapter, scan_phys=hci_scan_phys, print_live=args.debug)
    hci.start()

    # Give both radios a moment to settle on the advertising channels.
    wait_for_sniffer_ready(args.settle, "Waiting for both sniffers to stabilize...")

    def abort(reason: str) -> None:
        logger.error("Aborting: %s", reason)
        nrf.stop()
        nrf.join(timeout=3.0)
        hci.stop()
        hci.join(timeout=3.0)
        sys.exit(1)

    if hci.error or not hci.ready:
        abort(hci.error or f"HCI sniffer on {args.rx_adapter} did not start")
    if not nrf.ready or not nrf.is_alive():
        abort(f"nRF sniffer on {args.nrf_port} did not start")

    # --- Build the swarm -------------------------------------------------------
    base_lat, base_lng = BASE_LOCATION
    drones_config = []
    for _ in range(args.drones):
        lat, lng = random_location(base_lat, base_lng, 50000)
        drones_config.append({
            "mode": "random",
            "start_location": [lat / 1e7, lng / 1e7],
            "lifespan_seconds": safety,
        })

    spoof_args = argparse.Namespace(
        interface=args.tx_adapter,
        manual=False,
        random=args.drones,
        serial=None,
        interval=args.interval,
        location=BASE_LOCATION,
        verbose=False,
        transport="ble",
        ble_mode=norm_mode,
        no_self_id=True,
        no_operator_id=False,
        drones_config=drones_config,
    )

    backend = BleExtendedBackend(
        adapter=args.tx_adapter,
        legacy_interval_ms=args.ble_interval_ms,
        extended_interval_ms=args.ble_interval_ms,
        mode=norm_mode,
    )

    instrument_backend(backend, max_cycles=target_cycles)
    spoofer = DroneSpoofer(spoof_args, [backend])

    # --- Transmit --------------------------------------------------------------
    try:
        spoofer.run_automatic_mode()
    finally:
        backend.close()

    # Let trailing over-the-air packets drain into both receivers.
    time.sleep(2.0)

    nrf.stop()
    nrf.join(timeout=3.0)
    hci.stop()
    hci.join(timeout=3.0)

    # --- Correlate -------------------------------------------------------------
    mac_to_serial: Dict[str, str] = dict(getattr(backend, "registered_drones", {}))
    macs = list(mac_to_serial.keys())
    expected_records = list(getattr(backend, "expected_records", []))

    # Build receptions (mac -> [(ts, types, crc_ok, basic_id_serial, rf_channel)]) for
    # both receivers. The nRF thread keeps full parsed records (incl. crc_ok and the RF
    # channel); the HCI controller does not report the RF channel, so it is None there.
    # compute_reception does the CRC and serial-match checks and the channel tally.
    nrf_rx: Dict[str, List[tuple]] = {}
    with nrf.lock:
        for rec in nrf.raw_records:
            mac = str(rec.get("mac", "")).upper()
            if not mac:
                continue
            rid = rec.get("remote_id") or {}
            msgs = rid.get("parsed_messages", []) if isinstance(rid, dict) else []
            types = tuple(m.get("type", "Unknown") for m in msgs if isinstance(m, dict))
            nrf_rx.setdefault(mac, []).append(
                (rec.get("timestamp", 0.0), types, rec.get("crc_ok"),
                 _basic_id_serial(msgs), rec.get("rf_channel")))
    with hci.lock:
        hci_rx = {m: [(ts, types, crc_ok, bid, None) for ts, types, crc_ok, bid in v]
                  for m, v in hci.records.items()}

    nrf_stats = compute_reception(nrf_rx, expected_records, macs, mac_to_serial, num_buckets)
    hci_stats = compute_reception(hci_rx, expected_records, macs, mac_to_serial, num_buckets)

    # Guard against silently recording a dead receiver: a round in which a receiver
    # captured nothing (0 packets / no drones seen) is almost always a setup problem
    # -- e.g. an HCI controller whose extended scan never started reporting, or an
    # adapter that needs a down/up reset -- not a real 0% reception. Writing such a
    # round would contaminate the comparison, so fail loudly instead.
    for name, stats in (("nRF", nrf_stats), ("HCI", hci_stats)):
        if stats["drones_seen"] == 0 or stats["total_packets"] == 0:
            logger.error("!" * 70)
            logger.error("%s captured NOTHING this %s round (0 packets, 0 drones seen).",
                         name, label)
            logger.error("This is a receiver/adapter setup problem, not a real 0%% result.")
            logger.error("For an HCI adapter, reset it before retrying, e.g.:")
            logger.error("    sudo hciconfig %s down && sudo hciconfig %s up",
                         args.rx_adapter, args.rx_adapter)
            logger.error("Aborting so this run is not recorded as valid data.")
            logger.error("!" * 70)
            nrf.stop(); nrf.join(timeout=3.0)
            hci.stop(); hci.join(timeout=3.0)
            sys.exit(1)

    return {
        "mode": norm_mode,
        "label": label,
        "drones": args.drones,
        "duration": args.duration,
        "interval": args.interval,
        "num_buckets": num_buckets,
        "ble_interval_ms": args.ble_interval_ms,
        "expected_messages": nrf_stats["expected"],
        "mac_to_serial": mac_to_serial,
        "nrf": nrf_stats,
        "hci": hci_stats,
    }


def _agg(values: List[float]) -> Dict[str, float]:
    """Mean, sample std-dev, and standard error of the mean over repeated runs."""
    n = len(values)
    mean = statistics.fmean(values) if values else 0.0
    std = statistics.stdev(values) if n > 1 else 0.0
    sem = std / (n ** 0.5) if n > 1 else 0.0
    return {
        "mean": mean,
        "std": std,
        "sem": sem,
        "min": min(values) if values else 0.0,
        "max": max(values) if values else 0.0,
    }


def aggregate_runs(run_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Aggregate per-receiver statistics across repeated runs of one round."""
    out: Dict[str, Any] = {"n_runs": len(run_results)}
    for key in ("nrf", "hci"):
        stats = [r[key] for r in run_results]
        out[key] = {
            "pdr_percent": _agg([s["pdr_percent"] for s in stats]),
            "duplication_rate": _agg([s["duplication_rate"] for s in stats]),
            "median_iat_ms": _agg([s["median_iat_ms"] for s in stats]),
            "total_packets": _agg([float(s["total_packets"]) for s in stats]),
            "valid_packets": _agg([float(s["valid_packets"]) for s in stats]),
            "crc_failed_packets": _agg([float(s["crc_failed_packets"]) for s in stats]),
            "content_mismatch_packets": _agg([float(s["content_mismatch_packets"]) for s in stats]),
            "received": _agg([float(s["received"]) for s in stats]),
            "expected": _agg([float(s["expected"]) for s in stats]),
            "drones_seen": _agg([float(s["drones_seen"]) for s in stats]),
        }
    return out


def print_comparison(rounds: List[Dict[str, Any]]) -> None:
    print("\n" + "=" * 100)
    print("RECEPTION COMPARISON  (mean +/- std over N runs)")
    print("  PDR     = % of transmitted messages received via a CRC-valid, serial-matched frame (bounded 100%)")
    print("  Dup     = valid copies captured per transmitted message (BT4 = 3-channel/dwell redundancy)")
    print("  CRCfail = frames captured that failed CRC (diagnostic; ~0 at short range, excluded from PDR)")
    print("  Bad     = CRC-valid frames whose serial did not match what we sent (should be 0)")
    print("=" * 100)
    header = (f"{'Round':<16} | {'Rx':<4} | {'PDR mean+/-std':<17} | {'Dup mean+/-std':<16} | "
              f"{'CRCfail':<8} | {'Bad':<5}")
    print(header)
    print("-" * 100)
    for r in rounds:
        agg = r["aggregate"]
        for recv_name, key in (("nRF", "nrf"), ("HCI", "hci")):
            a = agg[key]
            pdr, dup = a["pdr_percent"], a["duplication_rate"]
            pdr_str = f"{pdr['mean']:5.1f} +/- {pdr['std']:4.1f}%"
            dup_str = f"{dup['mean']:5.2f} +/- {dup['std']:4.2f}"
            print(f"{r['label']:<16} | {recv_name:<4} | {pdr_str:<17} | {dup_str:<16} | "
                  f"{a['crc_failed_packets']['mean']:<8.1f} | {a['content_mismatch_packets']['mean']:<5.1f}")
        print("-" * 100)


def print_per_run(rounds: List[Dict[str, Any]]) -> None:
    print("\nPer-run PDR (%):")
    for r in rounds:
        for recv_name, key in (("nRF", "nrf"), ("HCI", "hci")):
            vals = [f"{run[key]['pdr_percent']:.1f}" for run in r["runs"]]
            print(f"  {r['label']:<16} {recv_name:<4}: {', '.join(vals)}")


def print_breakdown(rounds: List[Dict[str, Any]]) -> None:
    """Per-channel capture split and inter-arrival, pooled over runs.

    For BT4 legacy this shows the ~3 primary-channel copies behind the duplication
    rate (nRF reports the RF channel; an HCI controller does not). The median
    inter-arrival time shows how tightly the copies of one message are spaced.
    """
    print("\nCapture breakdown (valid frames, pooled over runs):")
    for r in rounds:
        for recv_name, key in (("nRF", "nrf"), ("HCI", "hci")):
            ch_total: Dict[str, int] = {}
            expected_total = 0
            for run in r["runs"]:
                for ch, n in run[key]["channel_counts"].items():
                    ch_total[ch] = ch_total.get(ch, 0) + n
                expected_total += run[key]["expected"]
            iat = r["aggregate"][key]["median_iat_ms"]["mean"]
            # copies-per-message per channel = channel frame count / expected messages
            parts = []
            for ch in sorted(ch_total, key=lambda c: (c == "n/a", c)):
                per_msg = (ch_total[ch] / expected_total) if expected_total else 0.0
                label = "chN/A" if ch == "n/a" else f"ch{ch}"
                parts.append(f"{label}={per_msg:.2f}")
            ch_str = "  ".join(parts) if parts else "(none)"
            print(f"  {r['label']:<16} {recv_name:<4}: copies/msg [{ch_str}]  median IAT={iat:.1f} ms")


def main() -> None:
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    default_out = os.path.join(repo_root, "evaluation", "data", "sniffer_comparison.json")

    p = argparse.ArgumentParser(description="Compare nRF vs HCI BLE Remote ID reception (BT5 then BT4).")
    p.add_argument("--tx-adapter", default="hci0", help="HCI adapter that transmits the drones (default: hci0)")
    p.add_argument("--rx-adapter", default="hci1", help="HCI adapter that scans/receives (default: hci1)")
    p.add_argument("--nrf-port", default="/dev/ttyACM0", help="Serial port of the nRF sniffer (default: /dev/ttyACM0)")
    p.add_argument("--drones", type=int, default=5, help="Number of drones to spoof (default: 5)")
    p.add_argument("--duration", type=float, default=20.0, help="Transmit duration per round in seconds (default: 20)")
    p.add_argument("--interval", type=float, default=1.0, help="Spoofer update interval in seconds (default: 1.0)")
    p.add_argument("--ble-interval-ms", type=int, default=100, help="BLE advertising interval in ms (default: 100)")
    p.add_argument("--rounds", nargs="+", choices=["extended", "ext_legacy"], default=["extended", "ext_legacy"],
                   help="Rounds to run, in order (default: extended ext_legacy)")
    p.add_argument("--runs", type=int, default=5, help="Repetitions of each round to average (default: 5)")
    p.add_argument("--settle", type=int, default=3, help="Seconds to let sniffers stabilize before TX (default: 3)")
    p.add_argument("-c", "--filter-channel", dest="filter_channels", type=int, nargs="+",
                   choices=range(0, 40), metavar="CH", help="Only count nRF packets on these RF channels")
    p.add_argument("--out", default=default_out, help="Output JSON path")
    p.add_argument("--debug", action="store_true", help="Print each received RID packet live")
    args = p.parse_args()

    # The nRF sniffer is mandatory -- auto-detect if the given port is absent,
    # and hard-fail if no dongle can be found (both receivers are required).
    if args.nrf_port and not os.path.exists(args.nrf_port):
        for cand in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"]:
            if os.path.exists(cand):
                args.nrf_port = cand
                break
        else:
            logger.error("No nRF sniffer serial port found (tried %s and fallbacks). "
                         "Both receivers are required; aborting.", args.nrf_port)
            sys.exit(1)

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)

    if args.runs < 1:
        p.error("--runs must be >= 1")

    print(f"\nTX adapter : {args.tx_adapter}")
    print(f"RX adapter : {args.rx_adapter} (HCI scan)")
    print(f"nRF sniffer: {args.nrf_port}")
    print(f"Drones     : {args.drones}  Duration: {args.duration}s/round  "
          f"BLE interval: {args.ble_interval_ms}ms")
    print(f"Rounds     : {', '.join(args.rounds)}  Runs/round: {args.runs}\n")

    rounds = []
    # Each round (mode) is repeated args.runs times; the per-run results are kept
    # and averaged so the thesis can report mean +/- std with a known sample size.
    for mode in args.rounds:
        run_results = []
        for run_idx in range(args.runs):
            logger.info("### %s -- run %d/%d ###", mode, run_idx + 1, args.runs)
            run_results.append(run_round(mode, args))
            if run_idx < args.runs - 1:
                logger.info("Cooldown before next run...")
                time.sleep(5.0)
        meta = run_results[0]
        rounds.append({
            "mode": meta["mode"],
            "label": meta["label"],
            "drones": meta["drones"],
            "duration": meta["duration"],
            "interval": meta["interval"],
            "ble_interval_ms": meta["ble_interval_ms"],
            "n_runs": len(run_results),
            "aggregate": aggregate_runs(run_results),
            "runs": run_results,
        })
        # Persist incrementally so a long multi-run session is never lost.
        with open(args.out, "w") as f:
            json.dump(rounds, f, indent=2)
        logger.info("Cooldown before next round...")
        time.sleep(5.0)

    logger.info("Saved comparison (%d round(s), %d run(s) each) to %s",
                len(rounds), args.runs, args.out)

    print_comparison(rounds)
    print_breakdown(rounds)
    if args.runs > 1:
        print_per_run(rounds)


if __name__ == "__main__":
    main()
