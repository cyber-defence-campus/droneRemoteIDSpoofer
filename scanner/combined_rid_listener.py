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
# ASTM F3411 Protocol Constants & Spec Parser (Imported from sniffparser.py)
# ============================================================================

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from sniffparser import (
    ASTM_OUI,
    APP_CODE_RID,
    BLE_RID_UUID,
    OPENDRONEID_EPOCH_2019,
    MSG_TYPE_NAMES,
    PROTO_VERSION_NAMES,
    ID_TYPE_NAMES,
    UA_TYPE_NAMES,
    STATUS_NAMES,
    HEIGHT_TYPE_NAMES,
    HORIZ_ACCURACY_NAMES,
    VERT_ACCURACY_NAMES,
    SPEED_ACCURACY_NAMES,
    TIMESTAMP_ACCURACY_NAMES,
    AUTH_TYPE_NAMES,
    DESC_TYPE_NAMES,
    OPERATOR_LOCATION_TYPE_NAMES,
    CLASSIFICATION_TYPE_NAMES,
    EU_CATEGORY_NAMES,
    EU_CLASS_NAMES,
    sanitize_ascii_string,
    decode_astm_message,
    parse_astm_payload,
)


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
    def __init__(
        self,
        db_path: Optional[str] = "rid_detections.db",
        timeout_s: float = 300.0,
        persist_interval_s: float = 0.0,
    ):
        self.db_path = db_path
        self.timeout_s = timeout_s
        self.persist_interval_s = persist_interval_s
        self.active_encounters: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.last_wal_checkpoint = time.time()

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
            
            # Auto-reconcile any lingering active encounters from prior runs that are past timeout_s
            now = time.time()
            conn.execute("UPDATE encounters SET is_active = 0 WHERE is_active = 1 AND (? - last_seen) > ?;",
                         (now, self.timeout_s))
            conn.commit()

    def update_with_packet(self, packet: Dict[str, Any]) -> str:
        """Update or create an active encounter from an incoming packet. Returns encounter_id."""
        mac = packet.get("mac", "UNKNOWN")
        serial = packet.get("serial_number")
        ts = packet.get("timestamp", time.time())
        transport = packet.get("transport", "unknown")
        ch_raw = packet.get("channel", "N/A")
        if transport in ("bt4", "bt5"):
            ch_str = f"BLE Ch {ch_raw}" if (isinstance(ch_raw, int) or (isinstance(ch_raw, str) and ch_raw.isdigit())) else str(ch_raw)
        elif transport in ("wifi", "nan"):
            ch_str = f"Wi-Fi Ch {ch_raw}" if (isinstance(ch_raw, int) or (isinstance(ch_raw, str) and ch_raw.isdigit())) else str(ch_raw)
        else:
            ch_str = str(ch_raw)
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
                    "last_persisted": 0.0,
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
                        # Downsample trajectory if stationary or dense (<1s dt and <~1m movement)
                        last_pt = enc["trajectory"][-1] if enc["trajectory"] else None
                        should_record = False
                        if last_pt is None:
                            should_record = True
                        else:
                            dt_pt = ts - last_pt[5]
                            if dt_pt >= 1.0 or abs(lat - last_pt[0]) > 0.00001 or abs(lon - last_pt[1]) > 0.00001:
                                should_record = True
                        if should_record:
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
                    op_val = msg.get("operator_id") or msg.get("id")
                    if op_val:
                        enc["operator_id"] = op_val

                elif m_type == "Self-ID":
                    desc_val = msg.get("description") or msg.get("desc")
                    if desc_val:
                        enc["self_id_desc"] = desc_val

            # Persist live progress (throttled to at most once per persist_interval_s or first packet)
            if (
                self.persist_interval_s <= 0.0
                or enc["packet_count"] == 1
                or (ts - enc.get("last_persisted", 0.0) >= self.persist_interval_s)
            ):
                self._persist_encounter(enc)
                enc["last_persisted"] = ts

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

            # Periodic WAL checkpoint every 5 minutes
            if now - self.last_wal_checkpoint > 300.0:
                self.last_wal_checkpoint = now
                if self.db_path:
                    try:
                        with sqlite3.connect(self.db_path) as conn:
                            conn.execute("PRAGMA wal_checkpoint(PASSIVE);")
                    except Exception:
                        pass
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

    def _set_channel(self, channel: int) -> bool:
        # Method 1: iw dev <iface> set channel <ch>
        try:
            res = subprocess.run(
                ["iw", "dev", self.interface, "set", "channel", str(channel)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

        # Method 2: iwconfig <iface> channel <ch>
        try:
            res = subprocess.run(
                ["iwconfig", self.interface, "channel", str(channel)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )
            if res.returncode == 0:
                return True
        except Exception:
            pass

        # Method 3: iw dev <iface> set freq <freq_mhz>
        freq = get_freq_for_channel(channel)
        if freq > 0:
            try:
                res = subprocess.run(
                    ["iw", "dev", self.interface, "set", "freq", str(freq)],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
                )
                if res.returncode == 0:
                    return True
            except Exception:
                pass

        return False

    def _hop_step(self, target_channel: int, dwell_time: float, switch_delay: float):
        if not self.running:
            return

        if switch_delay > 0:
            time.sleep(switch_delay)

        if not self.running:
            return

        success = self._set_channel(target_channel)
        if success:
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

                # Fast check for ASTM OUI (FA:0B:BC) in Vendor Specific IEs (0xDD) or NAN Action frames
                vendor_ie_idx = -1
                search_offset = 0
                while True:
                    idx = frame.find(ASTM_OUI, search_offset)
                    if idx == -1:
                        break
                    if idx >= 2 and frame[idx - 2] == 0xDD:
                        vendor_ie_idx = idx
                        break
                    search_offset = idx + 1

                is_nan = False
                radiotap_len = struct.unpack('<H', frame[2:4])[0] if (len(frame) >= 4 and frame[0] == 0x00) else 0

                if vendor_ie_idx == -1:
                    # Check for NAN Action frames (0xD0 / 0xE0)
                    if len(frame) > radiotap_len + 24:
                        fc = frame[radiotap_len]
                        if fc in (0xD0, 0xE0):
                            for offset in range(radiotap_len + 24, min(len(frame) - 4, radiotap_len + 128)):
                                if (frame[offset] >> 4) == 0xF and frame[offset + 1] == 0x19:
                                    is_nan = True
                                    nan_pack_offset = offset
                                    break
                    if not is_nan:
                        continue

                if len(frame) < radiotap_len + 24:
                    continue

                # Extract MAC Address (addr2 / transmitter address at offset radiotap_len + 10)
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
                    astm_payload = frame[nan_pack_offset:]
                else:
                    transport = "wifi"
                    ie_len = frame[vendor_ie_idx - 1]
                    if vendor_ie_idx + ie_len > len(frame):
                        continue
                    vendor_data = frame[vendor_ie_idx + 3 : vendor_ie_idx + ie_len]
                    if len(vendor_data) >= 2 and vendor_data[0] == APP_CODE_RID:
                        counter = vendor_data[1]
                        astm_payload = vendor_data[2:]
                    else:
                        counter = 0
                        astm_payload = vendor_data

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
        logger.info("[*] Starting BLE nRF Sniffer worker thread...")

        script_dir = os.path.dirname(os.path.abspath(__file__))
        candidate_paths = [
            os.path.join(script_dir, "nrf_bt_sniffer_json.py"),
            os.path.join(script_dir, "..", "evaluation", "nrf_bt_sniffer_json.py"),
            os.path.join(script_dir, "..", "nrf_bt_sniffer_json.py"),
        ]
        nrf_script = next((p for p in candidate_paths if os.path.exists(p)), candidate_paths[0])

        while self.running:
            # 1. Detect or verify UART serial port if live
            active_port = self.nrf_port
            if not active_port and not self.rx_pcap:
                for candidate in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyACM2", "/dev/ttyUSB0", "/dev/ttyUSB1"]:
                    if os.path.exists(candidate):
                        active_port = candidate
                        break

            if not active_port and not self.rx_pcap:
                logger.warning("[!] No nRF BLE sniffer device found on /dev/ttyACM* or /dev/ttyUSB*. Retrying in 3s...")
                time.sleep(3.0)
                continue

            # Kill any lingering nrfutil / sniffer instances
            subprocess.run(["killall", "-9", "nrfutil", "nrfutil-ble-sniffer", "nrfutil-ble-sni"],
                           stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
            time.sleep(0.3)

            cmd = [sys.executable, nrf_script, "--only-rid"]
            if active_port:
                cmd.extend(["--nrf-port", active_port])
            elif self.rx_pcap and os.path.exists(self.rx_pcap):
                cmd.extend(["--rx-pcap", self.rx_pcap])

            if self.coded or self.ble_mode in ("ble5", "extended", "pure_bt5", "bt5"):
                cmd.append("--coded")
            if self.ble_mode in ("ble5", "extended", "pure_bt5", "bt5"):
                cmd.append("-b")

            try:
                self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=sys.stderr, text=True, start_new_session=True)
                port_desc = active_port if active_port else self.rx_pcap
                logger.info(f"[*] BLE nRF Sniffer process active on {port_desc}.")

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
                        transport_type = str(rid_info.get("transport", "bt5")).lower()
                        pdu_type = str(record.get("pdu_type", "")).upper()
                        if (
                            "5" in transport_type
                            or "ext" in transport_type
                            or "AUX" in pdu_type
                            or "EXT" in pdu_type
                            or self.ble_mode in ("ble5", "extended", "pure_bt5", "bt5")
                        ):
                            transport = "bt5"
                        else:
                            transport = "bt4"

                        # If parsed_msgs is empty or missing fields, try parsing raw_hex if available
                        if not parsed_msgs and raw_hex:
                            try:
                                raw_bytes = bytes.fromhex(raw_hex)
                                uuid_idx = raw_bytes.find(BLE_RID_UUID)
                                if uuid_idx != -1:
                                    astm_p = raw_bytes[uuid_idx + 2:]
                                    if len(astm_p) >= 2 and astm_p[0] == 0x0D:
                                        astm_p = astm_p[2:]
                                    parsed_msgs, _ = parse_astm_payload(astm_p)
                            except Exception:
                                pass

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

                        rf_ch = record.get("rf_channel")
                        ch_str = f"Ch {rf_ch}" if rf_ch is not None else "Adv (37/38/39)"
                        freq_mhz = 2402
                        if rf_ch == 37:
                            freq_mhz = 2402
                        elif rf_ch == 38:
                            freq_mhz = 2426
                        elif rf_ch == 39:
                            freq_mhz = 2480
                        elif rf_ch is not None and 0 <= rf_ch <= 36:
                            freq_mhz = 2404 + 2 * rf_ch

                        event: Dict[str, Any] = {
                            "timestamp": ts,
                            "timestamp_iso": datetime.fromtimestamp(ts, timezone.utc).isoformat(),
                            "transport": transport,
                            "interface": "nRF52840-UART",
                            "channel": ch_str,
                            "band": "2.4GHz",
                            "frequency_mhz": freq_mhz,
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
                    logger.error(f"[-] Error running nrf_bt_sniffer_json.py: {e}")
            finally:
                self.stop_process()

            # If offline PCAP mode, stop after completion
            if self.rx_pcap or not self.running:
                break

            # If live sniffing and process ended unexpectedly, wait and retry
            logger.warning("[!] BLE nRF sniffer disconnected or exited. Reconnecting in 2.0s...")
            time.sleep(2.0)

        self.running = False
        logger.info("[*] BLE nRF Sniffer worker stopped.")

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
    1. Colorized live console display (or periodic quiet heartbeat in daemon mode).
    2. Append-only replay-compatible JSONL log with optional daily date splitting.
    3. SQLite 5-minute flight encounter grouping & throttled persistence with WAL checkpointing.
    """
    def __init__(
        self,
        log_jsonl_path: Optional[str] = None,
        db_path: Optional[str] = "rid_detections.db",
        encounter_timeout_s: float = 300.0,
        quiet: bool = False,
        rotate_daily: bool = False,
        persist_interval_s: float = 2.0,
    ):
        self.base_log_path = log_jsonl_path
        self.rotate_daily = rotate_daily
        self.quiet = quiet
        self.current_log_path: Optional[str] = None
        self.log_file_handle = None

        self.encounter_tracker = EncounterTracker(
            db_path=db_path,
            timeout_s=encounter_timeout_s,
            persist_interval_s=persist_interval_s
        ) if db_path else None

        self.stats = {
            "total_packets": 0,
            "transports": {"bt4": 0, "bt5": 0, "wifi": 0, "nan": 0},
            "macs": set(),
            "serials": set(),
            "wifi_channels": {},
            "ble_channels": {},
        }
        self.mac_to_serial: Dict[str, str] = {}
        self.start_time = time.time()
        self.first_packet_time: Optional[float] = None
        self.last_timeout_check = time.time()
        self.last_heartbeat = time.time()

    def _ensure_log_handle(self, now: float):
        if not self.base_log_path:
            return None

        if self.rotate_daily:
            dt_str = datetime.fromtimestamp(now, timezone.utc).strftime("%Y%m%d")
            root, ext = os.path.splitext(self.base_log_path)
            target = f"{root}_{dt_str}{ext or '.jsonl'}"
        else:
            target = self.base_log_path

        if target != self.current_log_path or self.log_file_handle is None:
            if self.log_file_handle:
                try:
                    self.log_file_handle.close()
                except Exception:
                    pass
            parent_dir = os.path.dirname(os.path.abspath(target))
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)
            self.current_log_path = target
            self.log_file_handle = open(target, "a")
            if not self.quiet:
                logger.info(f"[*] Replay telemetry logging to {target}")

        return self.log_file_handle

    def periodic_maintenance(self, now: Optional[float] = None):
        """
        Periodic maintenance task called continuously from the main loop even when the event queue is empty.
        1. Sweeps for encounters exceeding the silence timeout (> 5 minutes) and closes them in SQLite.
        2. In quiet / daemon mode, prints a periodic status heartbeat every 30 seconds.
        """
        if now is None:
            now = time.time()

        # 1. Sweep for timed-out encounters every 5 seconds
        if self.encounter_tracker and (now - self.last_timeout_check >= 5.0):
            closed = self.encounter_tracker.check_timeouts(now)
            for c_id in closed:
                if not self.quiet:
                    print(f"{C_GRAY}[*] Flight Encounter {c_id} closed ({self.encounter_tracker.timeout_s:.0f}s silence timeout).{C_RESET}")
            self.last_timeout_check = now

        # 2. In quiet mode, emit periodic heartbeat every 30s even when 0 packets arrive
        if self.quiet and (now - self.last_heartbeat >= 30.0):
            self.last_heartbeat = now
            iso_str = datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            active_cnt = len(self.encounter_tracker.active_encounters) if self.encounter_tracker else 0
            bt_cnt = self.stats["transports"].get("bt5", 0) + self.stats["transports"].get("bt4", 0)
            wifi_cnt = self.stats["transports"].get("wifi", 0) + self.stats["transports"].get("nan", 0)
            print(f"[STATUS {iso_str}] Total: {self.stats['total_packets']} pkts (BLE: {bt_cnt}, Wi-Fi: {wifi_cnt}) | Active Encounters: {active_cnt} | Unique Drones: {len(self.stats['macs'])}")
            sys.stdout.flush()

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

        ch_raw = event.get("channel")
        if t_key in ("bt4", "bt5"):
            ch_key = f"Ch {ch_raw}" if (isinstance(ch_raw, int) or (isinstance(ch_raw, str) and ch_raw.isdigit())) else str(ch_raw or "Adv")
            self.stats["ble_channels"][ch_key] = self.stats["ble_channels"].get(ch_key, 0) + 1
        elif t_key in ("wifi", "nan"):
            ch_key = str(ch_raw) if ch_raw is not None else "N/A"
            self.stats["wifi_channels"][ch_key] = self.stats["wifi_channels"].get(ch_key, 0) + 1

        # 1. Update SQLite 5-minute Encounter Tracker
        encounter_id = None
        if self.encounter_tracker:
            encounter_id = self.encounter_tracker.update_with_packet(event)

        # 2. Write to Replay-Compatible JSONL
        ev_ts = event.get("timestamp", now)
        handle = self._ensure_log_handle(ev_ts)
        if handle:
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
            handle.write(json.dumps(replay_record) + "\n")
            handle.flush()

        # In quiet mode, per-packet display is suppressed (heartbeats handled in periodic_maintenance)
        if self.quiet:
            return

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
        if t_key in ("bt4", "bt5"):
            ch_display = f"BLE {ch_raw}" if ch_raw and not str(ch_raw).startswith("BLE") else str(ch_raw or "Adv")
        else:
            ch_display = f"Ch {ch_raw}" if ch_raw and not str(ch_raw).startswith("Ch") else str(ch_raw or "")
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
                op_id = msg.get("operator_id") or msg.get("id")
                op_id_display = op_id if op_id else "None / Unset"
                op_id_type = msg.get("operator_id_type_name", "Operator ID")
                print(f"   {C_WHITE}👤 Operator  {C_RESET}{ver_tag} -> {op_id_type}: {op_id_display}")

            elif m_type == "Self-ID":
                desc = msg.get("description") or msg.get("desc")
                desc_display = desc if desc else "None / Unset"
                desc_type = msg.get("desc_type_name", "Text Description")
                print(f"   {C_WHITE}📝 Self-ID   {C_RESET}{ver_tag} -> [{desc_type}] \"{desc_display}\"")

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
            try:
                self.log_file_handle.close()
            except Exception:
                pass
            self.log_file_handle = None

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

        if self.stats["wifi_channels"]:
            print(f"  • Wi-Fi Channels Active (2.4GHz / 5.8GHz):")
            def _wifi_sort_key(c):
                try:
                    return (0, int(c))
                except ValueError:
                    return (1, str(c))
            for ch in sorted(self.stats["wifi_channels"].keys(), key=_wifi_sort_key):
                print(f"      - Channel {ch:<8}: {self.stats['wifi_channels'][ch]} packets")

        if self.stats["ble_channels"]:
            print(f"  • Bluetooth LE Channels Active:")
            for ch in sorted(self.stats["ble_channels"].keys()):
                print(f"      - {ch:<16}: {self.stats['ble_channels'][ch]} packets")

        print(f"{C_BOLD}{'='*60}{C_RESET}\n")


# ============================================================================
# Monitor Mode Setup Helpers
# ============================================================================

def setup_monitor_mode(interface: str, initial_channel: int = 6):
    """Put interface into monitor mode, unmanage from NetworkManager, and bring it up."""
    logger.info(f"[*] Configuring {interface} into monitor mode...")
    try:
        # Attempt to unmanage from NetworkManager to prevent channel hopping interference
        try:
            subprocess.run(["nmcli", "dev", "set", interface, "managed", "no"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
        except Exception:
            pass

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
    parser.add_argument("--wifi-channel", "--channel", "-c", type=int, default=None,
                        help="Lock Wi-Fi sniffer to a single fixed channel (e.g. 6 or 149) and disable hopping")
    parser.add_argument("--no-hop", action="store_true",
                        help="Disable Wi-Fi channel hopping (listen only on initial channel)")
    parser.add_argument("--non-social-ratio", "-k", type=int, default=1,
                        help="Non-social channel ratio multiplier k (cycles 2k non-social on 2.4GHz for every k on 5.8GHz)")
    parser.add_argument("--social-dwell-ms", type=int, default=1000, help="Social channel dwell time in milliseconds (1 Hz)")
    parser.add_argument("--non-social-dwell-ms", type=int, default=200, help="Non-social channel dwell time in milliseconds (5 Hz)")
    parser.add_argument("--intraband-delay-ms", type=int, default=30, help="Intraband channel switching delay in ms (empirical estimate, configurable for Wi-Fi chipset/driver)")
    parser.add_argument("--interband-delay-ms", type=int, default=50, help="Interband channel switching delay in ms (empirical estimate, configurable for Wi-Fi chipset/driver)")

    # BLE Options
    parser.add_argument("--coded", action="store_true", help="Enable Bluetooth 5 Long Range (LE Coded PHY) scanning")
    parser.add_argument("--ble-mode", choices=["all", "legacy", "extended"], default="extended", help="BLE advertisement filter mode (default: extended)")

    # Storage & Logging
    parser.add_argument("--db-file", default="rid_detections.db", help="SQLite database path for 5-minute flight encounter records (set empty '' to disable)")
    parser.add_argument("--encounter-timeout-s", type=float, default=300.0, help="Flight encounter timeout in seconds (default 300s / 5 minutes)")
    parser.add_argument("--persist-interval", type=float, default=2.0, help="Maximum frequency in seconds to persist active encounters to SQLite (default: 2.0s)")
    parser.add_argument("--log-jsonl", default=None, help="Optional replay-compatible JSONL log file path")
    parser.add_argument("--rotate-daily", action="store_true", help="Automatically split JSONL log file daily (<name>_YYYYMMDD.jsonl)")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet / daemon mode: suppress per-packet console banner and print periodic heartbeat status")

    args = parser.parse_args()

    if args.no_wifi and args.no_ble:
        logger.error("[-] Both Wi-Fi and BLE are disabled. Nothing to do!")
        sys.exit(1)

    if not args.no_wifi and not args.wifi_iface:
        logger.warning("[!] No --wifi-iface specified. Wi-Fi capture will be disabled unless --wifi-iface is provided.")
        args.no_wifi = True

    if os.geteuid() != 0 and not args.no_wifi:
        logger.warning("[!] Warning: Root privileges (sudo) are recommended for Wi-Fi monitor mode and raw socket capture.")

    initial_wifi_ch = args.wifi_channel if args.wifi_channel is not None else SOCIAL_CHANNEL_2G

    event_queue: queue.Queue = queue.Queue()
    channel_state = SharedChannelState(initial_channel=initial_wifi_ch)
    logger_worker = UnifiedTelemetryLogger(
        log_jsonl_path=args.log_jsonl,
        db_path=args.db_file if args.db_file else None,
        encounter_timeout_s=args.encounter_timeout_s,
        quiet=args.quiet,
        rotate_daily=args.rotate_daily,
        persist_interval_s=args.persist_interval,
    )

    threads: List[threading.Thread] = []
    hopper_thread: Optional[WifiChannelHopperThread] = None
    wifi_thread: Optional[WifiSnifferThread] = None
    ble_thread: Optional[BleNrfSnifferThread] = None

    # Setup Wi-Fi
    if not args.no_wifi:
        if not args.no_wifi_setup:
            setup_monitor_mode(args.wifi_iface, initial_channel=initial_wifi_ch)

        if not args.no_hop and args.wifi_channel is None:
            hopper_thread = WifiChannelHopperThread(
                interface=args.wifi_iface,
                channel_state=channel_state,
                non_social_ratio_k=args.non_social_ratio,
                social_dwell_ms=args.social_dwell_ms,
                non_social_dwell_ms=args.non_social_dwell_ms,
                intraband_delay_ms=args.intraband_delay_ms,
                interband_delay_ms=args.interband_delay_ms,
            )
            threads.append(hopper_thread)
        else:
            logger.info(f"[*] Wi-Fi sniffer locked to fixed Channel {initial_wifi_ch} (hopping disabled).")

        wifi_thread = WifiSnifferThread(
            interface=args.wifi_iface,
            channel_state=channel_state,
            event_queue=event_queue,
        )
        threads.append(wifi_thread)

    # Setup BLE
    if not args.no_ble:
        nrf_port = args.nrf_port
        if not nrf_port and not args.rx_pcap:
            for candidate in ["/dev/ttyACM0", "/dev/ttyACM1", "/dev/ttyUSB0"]:
                if os.path.exists(candidate):
                    nrf_port = candidate
                    logger.info(f"[*] Auto-detected nRF BLE sniffer on {candidate}")
                    break
        ble_thread = BleNrfSnifferThread(
            event_queue=event_queue,
            nrf_port=nrf_port,
            rx_pcap=args.rx_pcap,
            coded=args.coded or (args.ble_mode in ("ble5", "extended", "pure_bt5", "bt5")),
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
            now = time.time()
            try:
                event = event_queue.get(timeout=0.2)
                logger_worker.process_event(event)
            except queue.Empty:
                pass
            logger_worker.periodic_maintenance(now)
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
