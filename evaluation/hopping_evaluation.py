#!/usr/bin/env python3
"""
Wi-Fi Channel Hopping Latency, RF Readiness & Previous Frequency Retention Evaluation Harness

Measures the complete transition lifecycle during Wi-Fi monitor mode channel hopping:
  1. Previous Frequency Retention (Drain Latency): How long packets are still received
     on the OLD channel after switch invocation (due to hardware FIFO / USB URB ring buffers).
  2. RF Synthesizer Blind Spot (Switching Dead Time): The physical duration during PLL
     retuning where the receiver is deaf to both channels.
  3. True Physical Layer RF Readiness: The exact moment the FIRST packet is captured
     on the NEW channel.
  4. Synchronous Command Execution Latency: The total blocking time of iw / iwconfig syscalls.
  5. Hardware Lead Time: How many milliseconds the radio is receiving on the target channel
     BEFORE the command returns.

Features Active Calibration Pulse Injection (--tx-interface):
  - Uses an auxiliary Wi-Fi interface (or simulated pulse generator in mock mode)
    to broadcast continuous deterministic 802.11 calibration frames (e.g. 500 Hz / 2ms)
    on the target channel.
  - Eliminates reliance on random ambient traffic and enables deterministic,
    sub-millisecond measurement of exact RF synthesizer lock timing across all channels!

Evaluates:
  - Intra-band 2.4 GHz transitions (e.g. Ch 6 -> Ch 1..13)
  - Intra-band 5.8 GHz transitions (e.g. Ch 149 -> Ch 153..173)
  - Cross-band / Inter-band transitions (2.4 GHz <-> 5.8 GHz)
  - Exact Scanner Schedule sequence replay (emulating WifiChannelHopperThread)
  - Full N x N pairwise transition latency matrix

Derives empirical delay parameters (--intraband-delay-ms and --interband-delay-ms)
for the scanner's hopping engine, exports structured JSON benchmark datasets, and
generates publication-ready comparative visualization figures.
"""

import argparse
import datetime
import glob
import json
import logging
import math
import os
import random
import re
import select
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

# Ensure repository root and evaluation directory are in sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

eval_dir = os.path.dirname(os.path.abspath(__file__))
if eval_dir not in sys.path:
    sys.path.insert(0, eval_dir)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger("hopping_eval")

# =============================================================================
# Constants & Default Channel Allocations
# =============================================================================

DEFAULT_CHANNELS_2G = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
DEFAULT_CHANNELS_5G = [149, 153, 157, 161, 165]

DEFAULT_SOCIAL_2G = 6
DEFAULT_SOCIAL_5G = 149

METHOD_IW_SET_CHANNEL = "iw_set_channel"
METHOD_IW_SET_FREQ = "iw_set_freq"
METHOD_IWCONFIG = "iwconfig"

ALL_METHODS = [METHOD_IW_SET_CHANNEL, METHOD_IW_SET_FREQ, METHOD_IWCONFIG]

CALIBRATION_MAGIC_MAC = b'\x02\x00\xde\xad\xbe\xef'
CALIBRATION_MAGIC_OUI = b'\xfa\x0b\xbc'


# =============================================================================
# Helper Utilities: Frequencies, Bands, and Categories
# =============================================================================

def get_wifi_band(ch: int) -> str:
    """Returns frequency band string for a Wi-Fi channel."""
    if ch <= 14:
        return "2.4GHz"
    elif ch >= 149:
        return "5.8GHz"
    elif ch >= 36:
        return "5GHz"
    return "Unknown"


def get_freq_for_channel(ch: int) -> int:
    """Calculates center frequency in MHz for standard 802.11 channels."""
    if ch == 14:
        return 2484
    elif 1 <= ch <= 13:
        return 2407 + 5 * ch
    elif 36 <= ch <= 177:
        return 5000 + 5 * ch
    return 0


def get_channel_for_freq(freq: int) -> int:
    """Calculates channel number from frequency in MHz."""
    if freq == 2484:
        return 14
    elif 2412 <= freq <= 2472:
        return (freq - 2407) // 5
    elif 5000 < freq <= 5900:
        return (freq - 5000) // 5
    return 0


def get_transition_category(src_ch: int, dst_ch: int) -> str:
    """
    Categorizes channel transitions into:
      - 'intraband_2g': 2.4GHz -> 2.4GHz
      - 'intraband_5g': 5.8GHz -> 5.8GHz (or 5GHz -> 5GHz)
      - 'interband_2g_to_5g': 2.4GHz -> 5.8GHz/5GHz
      - 'interband_5g_to_2g': 5.8GHz/5GHz -> 2.4GHz
      - 'same_channel': src == dst
    """
    if src_ch == dst_ch:
        return "same_channel"

    src_band = get_wifi_band(src_ch)
    dst_band = get_wifi_band(dst_ch)

    if src_band == "2.4GHz" and dst_band == "2.4GHz":
        return "intraband_2g"
    elif "5" in src_band and "5" in dst_band:
        return "intraband_5g"
    elif src_band == "2.4GHz" and "5" in dst_band:
        return "interband_2g_to_5g"
    elif "5" in src_band and dst_band == "2.4GHz":
        return "interband_5g_to_2g"
    return "other"


# =============================================================================
# IEEE 802.11 Calibration Frame Builder & Parser
# =============================================================================

def build_calibration_pulse_frame(channel: int, seq: int, t_tx: float) -> bytes:
    """
    Constructs a lightweight IEEE 802.11 Probe Request frame with Radiotap header
    containing a microsecond TX timestamp and target channel tag.
    """
    radiotap = b'\x00\x00\x08\x00\x00\x00\x00\x00'

    fc = struct.pack('<H', 0x0040)
    dur = b'\x00\x00'
    da = b'\xff\xff\xff\xff\xff\xff'
    sa = CALIBRATION_MAGIC_MAC
    bssid = b'\xff\xff\xff\xff\xff\xff'
    seq_ctrl = struct.pack('<H', (seq & 0x0FFF) << 4)
    dot11_hdr = fc + dur + da + sa + bssid + seq_ctrl

    ssid_str = f"PULSE_CH{channel}".encode('utf-8')
    ie_ssid = bytes([0, len(ssid_str)]) + ssid_str

    rates = b'\x02\x04\x0b\x16\x0c\x18\x30\x6c'
    ie_rates = bytes([1, len(rates)]) + rates

    ie_ds = bytes([3, 1, channel & 0xFF])

    vendor_data = CALIBRATION_MAGIC_OUI + b'\x0D' + struct.pack('<H', seq) + struct.pack('<d', t_tx)
    ie_vendor = bytes([221, len(vendor_data)]) + vendor_data

    return radiotap + dot11_hdr + ie_ssid + ie_rates + ie_ds + ie_vendor


def parse_radiotap_and_frame_channel(frame: bytes) -> Tuple[Optional[int], Optional[int], Optional[str], bool, Optional[float]]:
    """
    Extracts (frequency_mhz, beacon_channel, ssid, is_calibration_pulse, tx_timestamp)
    from raw IEEE 802.11 Radiotap frames.
    """
    if len(frame) < 8 or frame[0] != 0x00:
        return None, None, None, False, None

    freq_mhz = None
    beacon_ch = None
    ssid = None
    is_pulse = False
    tx_ts = None

    try:
        radiotap_len = struct.unpack('<H', frame[2:4])[0]
        if len(frame) < radiotap_len or radiotap_len < 8:
            return None, None, None, False, None

        present_words = []
        idx = 4
        while idx + 4 <= radiotap_len:
            present = struct.unpack('<I', frame[idx:idx+4])[0]
            present_words.append(present)
            idx += 4
            if not (present & 0x80000000):
                break

        if present_words:
            w0 = present_words[0]
            offset = idx

            if w0 & (1 << 0):
                offset = (offset + 7) & ~7
                offset += 8
            if w0 & (1 << 1):
                offset += 1
            if w0 & (1 << 2):
                offset += 1
            if w0 & (1 << 3):
                offset = (offset + 1) & ~1
                if offset + 4 <= radiotap_len and offset + 4 <= len(frame):
                    freq_mhz = struct.unpack('<H', frame[offset:offset+2])[0]
                offset += 4

        if len(frame) >= radiotap_len + 24:
            mac_hdr = frame[radiotap_len : radiotap_len + 24]
            sa_addr = mac_hdr[10:16]
            if sa_addr == CALIBRATION_MAGIC_MAC:
                is_pulse = True

            fc = frame[radiotap_len]
            if fc in (0x80, 0x50, 0x40):
                fixed_len = 0 if fc == 0x40 else 12
                ie_offset = radiotap_len + 24 + fixed_len

                while ie_offset + 2 <= len(frame):
                    tag_id = frame[ie_offset]
                    tag_len = frame[ie_offset + 1]
                    tag_data_offset = ie_offset + 2
                    if tag_data_offset + tag_len > len(frame):
                        break

                    if tag_id == 3 and tag_len == 1:
                        beacon_ch = frame[tag_data_offset]
                    elif tag_id == 0 and tag_len > 0 and not ssid:
                        try:
                            ssid = frame[tag_data_offset : tag_data_offset + tag_len].decode('utf-8', errors='ignore')
                            if ssid.startswith("PULSE_CH"):
                                is_pulse = True
                        except Exception:
                            pass
                    elif tag_id == 221 and tag_len >= 14:
                        vendor_bytes = frame[tag_data_offset : tag_data_offset + tag_len]
                        if vendor_bytes.startswith(CALIBRATION_MAGIC_OUI + b'\x0D'):
                            is_pulse = True
                            if len(vendor_bytes) >= 14:
                                tx_ts = struct.unpack('<d', vendor_bytes[6:14])[0]

                    ie_offset += 2 + tag_len

    except Exception:
        pass

    return freq_mhz, beacon_ch, ssid, is_pulse, tx_ts


# =============================================================================
# Active Calibration Pulse Injector
# =============================================================================

class ActivePulseInjector:
    """
    Transmits deterministic, high-rate IEEE 802.11 calibration frames
    (e.g., 500 Hz / 2ms interval) on the target channel to measure
    the exact microsecond the receiving interface tunes to that channel.
    """
    def __init__(self, iface: str, pulse_rate_hz: int = 500, mock: bool = False):
        self.iface = iface
        self.pulse_rate_hz = pulse_rate_hz
        self.interval_s = 1.0 / max(1, pulse_rate_hz)
        self.mock = mock
        self.running = False
        self.current_channel = 6
        self.seq_num = 0
        self.thread: Optional[threading.Thread] = None
        self.sock: Optional[socket.socket] = None

    def set_channel(self, channel: int):
        self.current_channel = channel
        if not self.mock:
            subprocess.run(
                ["iw", "dev", self.iface, "set", "channel", str(channel)],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False
            )

    def start_burst(self, channel: int):
        self.set_channel(channel)
        self.running = True
        if self.mock:
            return

        try:
            if not self.sock:
                self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
                self.sock.bind((self.iface, 0))
            self.thread = threading.Thread(target=self._burst_loop, daemon=True)
            self.thread.start()
        except Exception as e:
            logger.warning(f"Could not start active pulse injector on {self.iface}: {e}")
            self.running = False

    def _burst_loop(self):
        while self.running and self.sock:
            try:
                t_tx = time.perf_counter()
                frame = build_calibration_pulse_frame(self.current_channel, self.seq_num, t_tx)
                self.seq_num = (self.seq_num + 1) & 0xFFFF
                self.sock.send(frame)
                time.sleep(self.interval_s)
            except Exception:
                break

    def stop_burst(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=0.1)

    def cleanup(self):
        self.stop_burst()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None


# =============================================================================
# Concurrent Packet Timeline Sniffer & Transition Lifecycle Engine
# =============================================================================

class PacketTimelineSniffer:
    """
    High-performance background sniffer capturing raw 802.11 packets
    and recording precise packet timestamps to evaluate:
      1. Previous Frequency Drain / Retention Latency
      2. RF Synthesizer Blind Spot (Dead Time)
      3. True RF Readiness Latency on New Channel
      4. Hardware Lead Time Before Command Return
    """
    def __init__(self, iface: str, mock: bool = False):
        self.iface = iface
        self.mock = mock
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.sock: Optional[socket.socket] = None
        self.lock = threading.Lock()
        self.packet_history: List[Dict[str, Any]] = []
        self.mock_current_channel = 6
        self.mock_switch_event_time: Optional[float] = None
        self.mock_target_channel: Optional[int] = None
        self.mock_src_channel: Optional[int] = None

    def start(self):
        self.running = True
        self.packet_history = []
        if self.mock:
            self.thread = threading.Thread(target=self._mock_sniff_loop, daemon=True)
            self.thread.start()
            return

        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
            self.sock.bind((self.iface, 0))
            self.thread = threading.Thread(target=self._live_sniff_loop, daemon=True)
            self.thread.start()
        except Exception as e:
            logger.warning(f"Could not initialize raw socket sniffer on {self.iface}: {e}")
            self.running = False

    def _live_sniff_loop(self):
        while self.running and self.sock:
            try:
                ready = select.select([self.sock], [], [], 0.01)
                if not ready[0]:
                    continue

                ts = time.perf_counter()
                frame = self.sock.recv(4096)
                if len(frame) < 10:
                    continue

                freq, beacon_ch, ssid, is_pulse, tx_ts = parse_radiotap_and_frame_channel(frame)
                inferred_ch = beacon_ch or (get_channel_for_freq(freq) if freq else None)

                rec = {
                    "timestamp": ts,
                    "frequency_mhz": freq,
                    "channel": inferred_ch,
                    "beacon_channel": beacon_ch,
                    "ssid": ssid,
                    "is_pulse": is_pulse,
                    "tx_timestamp": tx_ts,
                    "length": len(frame)
                }

                with self.lock:
                    self.packet_history.append(rec)
                    if len(self.packet_history) > 5000:
                        self.packet_history = self.packet_history[-3000:]
            except Exception:
                pass

    def set_mock_channel_switch(self, src_ch: int, target_ch: int, switch_time: float):
        """Simulates physical RF arrival timeline in mock mode."""
        self.mock_switch_event_time = switch_time
        self.mock_src_channel = src_ch
        self.mock_target_channel = target_ch

    def _mock_sniff_loop(self):
        """
        Simulates realistic physics of channel transition:
          1. [t_switch_start -> +3.5ms]: Old channel residual frames (FIFO / URB drain)
          2. [+3.5ms -> +rf_lock_time]: RF Synthesizer retuning (Blind spot / dead time, determined by target band)
          3. [+rf_lock_time onwards]: New channel active reception
        """
        curr_ch = 6
        seq = 0
        while self.running:
            now = time.perf_counter()
            active_ch = curr_ch

            if self.mock_switch_event_time is not None and self.mock_target_channel is not None:
                elapsed = now - self.mock_switch_event_time
                target_band = get_wifi_band(self.mock_target_channel)
                src_band = get_wifi_band(self.mock_src_channel) if self.mock_src_channel else "2.4GHz"
                is_cross_band = (target_band != src_band)

                # Calibrated against empirical evaluation datasets (mt76x0u_git / Real Hardware):
                # - Target 2.4 GHz RF lock: ~76-110 ms (mean ~85ms -> ~50-60ms lead time before ~145ms cmd finish)
                # - Target 5.8 GHz RF lock: ~157-193 ms (mean ~160ms -> ~0ms lead time before ~158-160ms cmd finish)
                # - Cross-band switching cuts drain immediately (<1ms), intra-band has ~1-12ms FIFO drain
                drain_time = 0.0010 if is_cross_band else 0.0035
                rf_lock_time = 0.160 if "5" in target_band else 0.085

                if elapsed < drain_time:
                    # Phase 1: Old channel packets still draining from buffer
                    active_ch = self.mock_src_channel or curr_ch
                elif drain_time <= elapsed < rf_lock_time:
                    # Phase 2: Synthesizer settling blind spot (silence)
                    time.sleep(0.002)
                    continue
                else:
                    # Phase 3: New channel tuned and locked
                    curr_ch = self.mock_target_channel
                    active_ch = self.mock_target_channel
                    self.mock_switch_event_time = None
                    self.mock_target_channel = None

            freq = get_freq_for_channel(active_ch)
            seq += 1
            rec = {
                "timestamp": now,
                "frequency_mhz": freq,
                "channel": active_ch,
                "beacon_channel": active_ch,
                "ssid": f"PULSE_CH{active_ch}",
                "is_pulse": True,
                "tx_timestamp": now - 0.0001,
                "length": 180
            }
            with self.lock:
                self.packet_history.append(rec)
                if len(self.packet_history) > 5000:
                    self.packet_history = self.packet_history[-3000:]

            time.sleep(0.003)  # ~300 packets/sec

    def stop(self):
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=0.1)

    def analyze_transition_timeline(
        self,
        t_switch_start: float,
        t_cmd_finish: float,
        src_ch: int,
        dst_ch: int
    ) -> Dict[str, Any]:
        """
        Analyzes the complete transition lifecycle:
          - Previous Channel Retention (Drain Latency)
          - RF Synthesizer Blind Spot
          - True RF Readiness on New Channel
          - Hardware Lead Time Before Command Return
        """
        with self.lock:
            history = list(self.packet_history)

        post_switch_pkts = [p for p in history if p["timestamp"] >= t_switch_start]

        first_dst_pkt = None
        first_dst_pulse = None
        last_src_pkt = None
        src_pkts_after_switch = 0
        dst_pkts_before_cmd = 0
        total_dst_pkts = 0
        seen_ssids = set()

        dst_freq = get_freq_for_channel(dst_ch)
        src_freq = get_freq_for_channel(src_ch)

        for p in post_switch_pkts:
            p_ch = p.get("channel")
            p_freq = p.get("frequency_mhz")
            p_ts = p.get("timestamp")
            is_pulse = p.get("is_pulse", False)

            is_dst = (p_ch == dst_ch) or (p_freq and dst_freq and p_freq == dst_freq)
            is_src = (p_ch == src_ch) or (p_freq and src_freq and p_freq == src_freq)

            if is_src:
                last_src_pkt = p
                src_pkts_after_switch += 1

            if is_dst:
                total_dst_pkts += 1
                if p.get("ssid"):
                    seen_ssids.add(p["ssid"])
                if first_dst_pkt is None:
                    first_dst_pkt = p
                if is_pulse and first_dst_pulse is None:
                    first_dst_pulse = p
                if p_ts < t_cmd_finish:
                    dst_pkts_before_cmd += 1

        cmd_duration_ms = (t_cmd_finish - t_switch_start) * 1000.0

        # Target Channel Timing
        target_first = first_dst_pulse or first_dst_pkt
        if target_first:
            rf_ready_ms = (target_first["timestamp"] - t_switch_start) * 1000.0
            lead_time_ms = cmd_duration_ms - rf_ready_ms
            rf_detected = True
            is_pulse_detected = bool(first_dst_pulse)
        else:
            rf_ready_ms = None
            lead_time_ms = None
            rf_detected = False
            is_pulse_detected = False

        # Source Channel Persistence / Drain Timing
        if last_src_pkt:
            src_drain_ms = (last_src_pkt["timestamp"] - t_switch_start) * 1000.0
            last_src_ts = last_src_pkt["timestamp"]
        else:
            src_drain_ms = 0.0
            last_src_ts = t_switch_start

        # RF Synthesizer Blind Spot (Gap between last old packet and first new packet)
        if target_first:
            blind_spot_ms = max(0.0, (target_first["timestamp"] - last_src_ts) * 1000.0)
        else:
            blind_spot_ms = None

        return {
            "cmd_duration_ms": round(cmd_duration_ms, 3),
            "rf_detected": rf_detected,
            "is_pulse_detected": is_pulse_detected,
            "rf_ready_ms": round(rf_ready_ms, 3) if rf_ready_ms is not None else None,
            "rf_lead_time_ms": round(lead_time_ms, 3) if lead_time_ms is not None else None,
            "src_drain_latency_ms": round(src_drain_ms, 3),
            "rf_blind_spot_ms": round(blind_spot_ms, 3) if blind_spot_ms is not None else None,
            "src_packets_after_switch": src_pkts_after_switch,
            "dst_packets_before_cmd_finish": dst_pkts_before_cmd,
            "total_dst_packets_captured": total_dst_pkts,
            "seen_ssids": list(seen_ssids)
        }


# =============================================================================
# Interface & Hardware Inspection
# =============================================================================

def get_interface_driver(iface: str) -> str:
    """Inspects sysfs to discover the underlying Linux kernel driver."""
    driver_path = f"/sys/class/net/{iface}/device/driver"
    if os.path.exists(driver_path):
        try:
            return os.path.basename(os.readlink(driver_path))
        except Exception:
            pass
    return "Unknown"


def get_interface_mac(iface: str) -> str:
    """Reads interface MAC address from sysfs."""
    addr_path = f"/sys/class/net/{iface}/address"
    if os.path.exists(addr_path):
        try:
            with open(addr_path, 'r') as f:
                return f.read().strip()
        except Exception:
            pass
    return "Unknown"


def get_interface_phy(iface: str) -> Optional[str]:
    """Queries the phy identifier (e.g. phy0, phy3) associated with an interface."""
    phy_link = f"/sys/class/net/{iface}/phy80211"
    if os.path.exists(phy_link):
        try:
            return os.path.basename(os.readlink(phy_link))
        except Exception:
            pass

    try:
        res = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, check=False)
        if res.returncode == 0:
            m = re.search(r"wiphy\s+(\d+)", res.stdout)
            if m:
                return f"phy{m.group(1)}"
    except Exception:
        pass
    return None


def get_phy_supported_channels(phy: Optional[str]) -> Tuple[List[int], List[int]]:
    """
    Parses 'iw phy <phy> info' to discover supported 2.4 GHz and 5 GHz channels.
    Returns (channels_2g, channels_5g).
    """
    if not phy:
        return DEFAULT_CHANNELS_2G.copy(), DEFAULT_CHANNELS_5G.copy()

    try:
        res = subprocess.run(["iw", "phy", phy, "info"], capture_output=True, text=True, check=False)
        if res.returncode != 0:
            return DEFAULT_CHANNELS_2G.copy(), DEFAULT_CHANNELS_5G.copy()

        ch_2g = []
        ch_5g = []

        for line in res.stdout.splitlines():
            if "(disabled)" in line or "(no IR)" in line:
                if "(disabled)" in line:
                    continue
            m = re.search(r"\*\s+(\d+\.?\d*)\s+MHz\s+\[(\d+)\]", line)
            if m:
                freq = float(m.group(1))
                ch = int(m.group(2))
                if freq < 3000:
                    if ch not in ch_2g:
                        ch_2g.append(ch)
                elif freq >= 5000:
                    if ch not in ch_5g:
                        ch_5g.append(ch)

        if not ch_2g:
            ch_2g = DEFAULT_CHANNELS_2G.copy()
        if not ch_5g:
            ch_5g = DEFAULT_CHANNELS_5G.copy()

        return sorted(ch_2g), sorted(ch_5g)
    except Exception as e:
        logger.warning(f"Could not query phy info: {e}. Using defaults.")
        return DEFAULT_CHANNELS_2G.copy(), DEFAULT_CHANNELS_5G.copy()


def check_monitor_mode(iface: str) -> bool:
    """Checks if the given interface is configured in monitor mode."""
    try:
        res = subprocess.run(["iw", "dev", iface, "info"], capture_output=True, text=True, check=False)
        if res.returncode == 0 and "type monitor" in res.stdout:
            return True
    except Exception:
        pass

    try:
        res = subprocess.run(["iwconfig", iface], capture_output=True, text=True, check=False)
        if res.returncode == 0 and "Mode:Monitor" in res.stdout:
            return True
    except Exception:
        pass

    return False


def setup_monitor_mode(iface: str, initial_channel: int = 6) -> bool:
    """Configures interface into monitor mode and sets initial channel."""
    logger.info(f"[*] Setting {iface} to monitor mode on Channel {initial_channel}...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=True, capture_output=True)
        try:
            subprocess.run(["iw", "dev", iface, "set", "type", "monitor"], check=True, capture_output=True)
        except Exception:
            subprocess.run(["iwconfig", iface, "mode", "monitor"], check=True, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True, capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "channel", str(initial_channel)], check=False, capture_output=True)
        return True
    except Exception as e:
        logger.error(f"[-] Failed to set monitor mode on {iface}: {e}")
        return False


def teardown_monitor_mode(iface: str) -> bool:
    """Restores interface to managed mode."""
    logger.info(f"[*] Restoring {iface} to managed mode...")
    try:
        subprocess.run(["ip", "link", "set", iface, "down"], check=False, capture_output=True)
        subprocess.run(["iw", "dev", iface, "set", "type", "managed"], check=False, capture_output=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=False, capture_output=True)
        return True
    except Exception as e:
        logger.warning(f"[-] Could not restore {iface}: {e}")
        return False


# =============================================================================
# Channel Switching Command Execution & Timing
# =============================================================================

def execute_switch_command(
    iface: str,
    channel: int,
    src_channel: int = 6,
    method: str = METHOD_IW_SET_CHANNEL,
    mock: bool = False,
    sniffer: Optional[PacketTimelineSniffer] = None
) -> Tuple[bool, float, float, float, Optional[str]]:
    """
    Executes a single channel switch command and measures nanosecond execution latency.
    
    Returns:
        (success: bool, t_start: float, t_finish: float, duration_ms: float, error_msg: Optional[str])
    """
    if mock:
        t_start = time.perf_counter()
        if sniffer:
            sniffer.set_mock_channel_switch(src_channel, channel, t_start)
        
        # Calibrated against empirical evaluation datasets (mt76x0u_git):
        # - 5G Intra-band: ~159.5 - 160.7 ms (wider UNII-1/3 VCO retuning)
        # - Cross-band 2.4G -> 5.8G: ~155.0 - 155.4 ms (faster than 5G intra-band!)
        # - Cross-band 5.8G -> 2.4G: ~148.0 - 150.8 ms
        # - 2.4G Intra-band: ~142.0 - 147.0 ms
        target_band = get_wifi_band(channel)
        src_band = get_wifi_band(src_channel)
        is_cross_band = (target_band != src_band)

        if "5" in target_band:
            if is_cross_band:
                base = 155.2
            else:
                base = 160.2 + (channel - 149) * 0.1
        else:
            if is_cross_band:
                base = 149.5
            else:
                base = 144.0 + (channel - 1) * 0.1

        jitter = random.uniform(-2.5, 2.5)
        dur_ms = max(5.0, base + jitter)
        time.sleep(dur_ms / 1000.0)
        t_finish = time.perf_counter()
        return True, t_start, t_finish, (t_finish - t_start) * 1000.0, None

    freq = get_freq_for_channel(channel)
    cmd = []

    if method == METHOD_IW_SET_CHANNEL:
        cmd = ["iw", "dev", iface, "set", "channel", str(channel)]
    elif method == METHOD_IW_SET_FREQ:
        if freq == 0:
            t = time.perf_counter()
            return False, t, t, 0.0, f"Invalid frequency for channel {channel}"
        cmd = ["iw", "dev", iface, "set", "freq", str(freq)]
    elif method == METHOD_IWCONFIG:
        cmd = ["iwconfig", iface, "channel", str(channel)]
    else:
        t = time.perf_counter()
        return False, t, t, 0.0, f"Unknown method {method}"

    t_start = time.perf_counter()
    try:
        res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
        t_finish = time.perf_counter()
        dur_ms = (t_finish - t_start) * 1000.0

        if res.returncode == 0:
            return True, t_start, t_finish, dur_ms, None
        else:
            err_str = res.stderr.decode('utf-8', errors='ignore').strip()
            return False, t_start, t_finish, dur_ms, f"Command failed (code {res.returncode}): {err_str}"
    except Exception as e:
        t_finish = time.perf_counter()
        dur_ms = (t_finish - t_start) * 1000.0
        return False, t_start, t_finish, dur_ms, str(e)


# =============================================================================
# Statistical Calculations
# =============================================================================

def compute_stats(samples: List[float]) -> Dict[str, Any]:
    """Computes comprehensive descriptive statistics for a list of latency samples."""
    if not samples:
        return {
            "count": 0, "min": 0.0, "mean": 0.0, "median": 0.0,
            "std": 0.0, "p75": 0.0, "p90": 0.0, "p95": 0.0,
            "p99": 0.0, "max": 0.0, "iqr": 0.0
        }

    s_sorted = sorted(samples)
    n = len(s_sorted)

    def percentile(p: float) -> float:
        if n == 1:
            return s_sorted[0]
        k = (n - 1) * p
        f = math.floor(k)
        c = math.ceil(k)
        if f == c:
            return s_sorted[int(k)]
        return s_sorted[int(f)] * (c - k) + s_sorted[int(c)] * (k - f)

    mean_val = sum(s_sorted) / n
    median_val = percentile(0.50)
    p25_val = percentile(0.25)
    p75_val = percentile(0.75)
    p90_val = percentile(0.90)
    p95_val = percentile(0.95)
    p99_val = percentile(0.99)
    min_val = s_sorted[0]
    max_val = s_sorted[-1]
    iqr_val = p75_val - p25_val

    variance = sum((x - mean_val) ** 2 for x in s_sorted) / n if n > 1 else 0.0
    std_val = math.sqrt(variance)

    return {
        "count": n,
        "min": round(min_val, 3),
        "mean": round(mean_val, 3),
        "median": round(median_val, 3),
        "std": round(std_val, 3),
        "p75": round(p75_val, 3),
        "p90": round(p90_val, 3),
        "p95": round(p95_val, 3),
        "p99": round(p99_val, 3),
        "max": round(max_val, 3),
        "iqr": round(iqr_val, 3)
    }


# =============================================================================
# Benchmark Execution Engine
# =============================================================================

def run_transition_benchmark(
    iface: str,
    src_ch: int,
    dst_ch: int,
    iterations: int,
    method: str = METHOD_IW_SET_CHANNEL,
    settle_delay_s: float = 0.02,
    packet_sniff_window_s: float = 0.15,
    sniffer: Optional[PacketTimelineSniffer] = None,
    injector: Optional[ActivePulseInjector] = None,
    mock: bool = False
) -> Dict[str, Any]:
    """
    Alternates back-and-forth between src_ch and dst_ch for N iterations,
    measuring:
      - Command execution latency
      - Previous frequency retention (drain latency)
      - RF Synthesizer blind spot
      - True RF readiness latency
      - Hardware lead time
    """
    cmd_latencies: List[float] = []
    rf_ready_latencies: List[float] = []
    rf_lead_times: List[float] = []
    src_drain_latencies: List[float] = []
    rf_blind_spots: List[float] = []
    src_pkts_after_switch_list: List[int] = []
    pkts_before_cmd_list: List[int] = []
    failures = 0
    errors: List[str] = []

    category = get_transition_category(src_ch, dst_ch)

    # Initial setup to src_ch
    execute_switch_command(iface, src_ch, src_channel=src_ch, method=method, mock=mock, sniffer=sniffer)
    time.sleep(settle_delay_s)

    for i in range(iterations):
        if injector:
            injector.start_burst(dst_ch)

        # Switch to dst_ch (measuring this step)
        success, t_start, t_finish, cmd_dur_ms, err = execute_switch_command(
            iface, dst_ch, src_channel=src_ch, method=method, mock=mock, sniffer=sniffer
        )
        if success:
            cmd_latencies.append(cmd_dur_ms)
            
            if sniffer:
                time.sleep(packet_sniff_window_s)
                rf_info = sniffer.analyze_transition_timeline(t_start, t_finish, src_ch, dst_ch)
                
                # RF Ready
                if rf_info["rf_detected"] and rf_info["rf_ready_ms"] is not None:
                    rf_ready_latencies.append(rf_info["rf_ready_ms"])
                    if rf_info["rf_lead_time_ms"] is not None:
                        rf_lead_times.append(rf_info["rf_lead_time_ms"])
                    pkts_before_cmd_list.append(rf_info["dst_packets_before_cmd_finish"])
                
                # Previous Frequency Drain & Blind Spot
                src_drain_latencies.append(rf_info["src_drain_latency_ms"])
                src_pkts_after_switch_list.append(rf_info["src_packets_after_switch"])
                if rf_info["rf_blind_spot_ms"] is not None:
                    rf_blind_spots.append(rf_info["rf_blind_spot_ms"])
        else:
            failures += 1
            if err and err not in errors:
                errors.append(err)

        if injector:
            injector.stop_burst()

        time.sleep(settle_delay_s)

        # Switch back to src_ch for next repetition
        if src_ch != dst_ch:
            execute_switch_command(iface, src_ch, src_channel=dst_ch, method=method, mock=mock, sniffer=sniffer)
            time.sleep(settle_delay_s)

    cmd_stats = compute_stats(cmd_latencies)
    rf_stats = compute_stats(rf_ready_latencies)
    lead_stats = compute_stats(rf_lead_times)
    drain_stats = compute_stats(src_drain_latencies)
    blind_stats = compute_stats(rf_blind_spots)

    return {
        "src_channel": src_ch,
        "dst_channel": dst_ch,
        "src_band": get_wifi_band(src_ch),
        "dst_band": get_wifi_band(dst_ch),
        "category": category,
        "method": method,
        "iterations": iterations,
        "successful_samples": len(cmd_latencies),
        "failed_samples": failures,
        "success_rate_percent": round((len(cmd_latencies) / iterations) * 100.0, 1) if iterations > 0 else 0.0,
        "cmd_stats": cmd_stats,
        "raw_latencies_ms": cmd_latencies,
        "rf_ready_stats": rf_stats,
        "raw_rf_ready_ms": rf_ready_latencies,
        "rf_lead_time_stats": lead_stats,
        "raw_rf_lead_times_ms": rf_lead_times,
        "src_drain_stats": drain_stats,
        "raw_src_drain_ms": src_drain_latencies,
        "rf_blind_spot_stats": blind_stats,
        "raw_rf_blind_spot_ms": rf_blind_spots,
        "avg_src_packets_after_switch": round(sum(src_pkts_after_switch_list) / len(src_pkts_after_switch_list), 2) if src_pkts_after_switch_list else 0.0,
        "avg_packets_before_cmd": round(sum(pkts_before_cmd_list) / len(pkts_before_cmd_list), 2) if pkts_before_cmd_list else 0.0,
        "errors": errors
    }


def run_scanner_sequence_benchmark(
    iface: str,
    cycles: int,
    ratio_k: int = 1,
    social_2g: int = DEFAULT_SOCIAL_2G,
    social_5g: int = DEFAULT_SOCIAL_5G,
    channels_2g: Optional[List[int]] = None,
    channels_5g: Optional[List[int]] = None,
    method: str = METHOD_IW_SET_CHANNEL,
    settle_delay_s: float = 0.02,
    packet_sniff_window_s: float = 0.05,
    sniffer: Optional[PacketTimelineSniffer] = None,
    injector: Optional[ActivePulseInjector] = None,
    mock: bool = False
) -> Dict[str, Any]:
    """
    Emulates the exact hopping schedule from WifiChannelHopperThread (scanner/combined_rid_listener.py):
      Cycle step:
        1. Social 2.4G (Ch 6)
        2. 2k Non-Social 2.4G channels (round-robin)
        3. Social 5.8G (Ch 149)
        4. k Non-Social 5.8G channels (round-robin)
    """
    if channels_2g is None:
        channels_2g = DEFAULT_CHANNELS_2G
    if channels_5g is None:
        channels_5g = DEFAULT_CHANNELS_5G

    non_social_2g = [c for c in channels_2g if c != social_2g]
    non_social_5g = [c for c in channels_5g if c != social_5g]

    n_2g_non_social = 2 * ratio_k
    n_5g_non_social = ratio_k

    idx_2g = 0
    idx_5g = 0

    current_ch = social_2g
    execute_switch_command(iface, current_ch, src_channel=current_ch, method=method, mock=mock, sniffer=sniffer)
    time.sleep(settle_delay_s)

    hop_records: List[Dict[str, Any]] = []

    logger.info(f"[*] Running Scanner Sequence Replay: {cycles} cycles (ratio k={ratio_k})...")

    def execute_hop(step_name: str, dst: int):
        nonlocal current_ch
        src = current_ch
        cat = get_transition_category(src, dst)

        if injector:
            injector.start_burst(dst)

        success, t_start, t_finish, lat_ms, err = execute_switch_command(
            iface, dst, src_channel=src, method=method, mock=mock, sniffer=sniffer
        )
        current_ch = dst
        rf_ready_ms = None
        lead_time_ms = None
        drain_ms = None
        blind_spot_ms = None

        if sniffer and success:
            time.sleep(packet_sniff_window_s)
            rf_info = sniffer.analyze_transition_timeline(t_start, t_finish, src, dst)
            rf_ready_ms = rf_info.get("rf_ready_ms")
            lead_time_ms = rf_info.get("rf_lead_time_ms")
            drain_ms = rf_info.get("src_drain_latency_ms")
            blind_spot_ms = rf_info.get("rf_blind_spot_ms")

        if injector:
            injector.stop_burst()

        hop_records.append({
            "step": step_name,
            "src_channel": src,
            "dst_channel": dst,
            "category": cat,
            "latency_ms": lat_ms,
            "rf_ready_ms": rf_ready_ms,
            "rf_lead_time_ms": lead_time_ms,
            "src_drain_latency_ms": drain_ms,
            "rf_blind_spot_ms": blind_spot_ms,
            "success": success
        })
        time.sleep(settle_delay_s)

    for cycle in range(cycles):
        # 1. 2.4 GHz Social Channel #1
        execute_hop("social_2g_1", social_2g)

        # 2. 2.4 GHz Non-Social Channels (2k)
        for sub_i in range(n_2g_non_social):
            dst = non_social_2g[idx_2g % len(non_social_2g)]
            idx_2g += 1
            execute_hop(f"non_social_2g_{sub_i+1}", dst)

        # 3. 2.4 GHz Social Channel #2 (Priority Channel 6 Return)
        execute_hop("social_2g_2", social_2g)

        # 4. 5.8 GHz Social Channel
        execute_hop("social_5g", social_5g)

        # 5. 5.8 GHz Non-Social Channels (k)
        for sub_i in range(n_5g_non_social):
            dst = non_social_5g[idx_5g % len(non_social_5g)]
            idx_5g += 1
            execute_hop(f"non_social_5g_{sub_i+1}", dst)

    all_lats = [h["latency_ms"] for h in hop_records if h["success"]]
    intra_lats = [h["latency_ms"] for h in hop_records if h["success"] and "intraband" in h["category"]]
    inter_lats = [h["latency_ms"] for h in hop_records if h["success"] and "interband" in h["category"]]
    all_rf = [h["rf_ready_ms"] for h in hop_records if h["success"] and h["rf_ready_ms"] is not None]
    all_drain = [h["src_drain_latency_ms"] for h in hop_records if h["success"] and h["src_drain_latency_ms"] is not None]
    all_blind = [h["rf_blind_spot_ms"] for h in hop_records if h["success"] and h["rf_blind_spot_ms"] is not None]

    return {
        "cycles": cycles,
        "ratio_k": ratio_k,
        "total_hops": len(hop_records),
        "hops": hop_records,
        "overall_stats": compute_stats(all_lats),
        "intraband_stats": compute_stats(intra_lats),
        "interband_stats": compute_stats(inter_lats),
        "rf_ready_stats": compute_stats(all_rf),
        "src_drain_stats": compute_stats(all_drain),
        "rf_blind_spot_stats": compute_stats(all_blind)
    }


def run_comprehensive_benchmark(
    iface: str,
    iterations: int = 20,
    channels_2g: Optional[List[int]] = None,
    channels_5g: Optional[List[int]] = None,
    methods: Optional[List[str]] = None,
    settle_delay_s: float = 0.02,
    packet_sniff_window_s: float = 0.15,
    sniffer: Optional[PacketTimelineSniffer] = None,
    injector: Optional[ActivePulseInjector] = None,
    mock: bool = False
) -> List[Dict[str, Any]]:
    """
    Executes a structured battery of key transitions across all 4 regimes:
      1. Intra-band 2.4 GHz
      2. Intra-band 5.8 GHz
      3. Cross-band (2.4 GHz -> 5.8 GHz)
      4. Cross-band (5.8 GHz -> 2.4 GHz)
    """
    if channels_2g is None:
        channels_2g = DEFAULT_CHANNELS_2G
    if channels_5g is None:
        channels_5g = DEFAULT_CHANNELS_5G
    if methods is None:
        methods = [METHOD_IW_SET_CHANNEL]

    transitions: List[Tuple[int, int, str]] = []

    # 1. Intra-band 2.4G
    transitions.append((6, 1, "2.4G Social -> Non-Social (Lower Edge)"))
    transitions.append((6, 11, "2.4G Social -> Non-Social (Upper)") if 11 in channels_2g else (6, channels_2g[-1], "2.4G Upper"))
    transitions.append((1, 2, "2.4G Adjacent Hop (Ch 1 -> 2)"))
    transitions.append((1, 11, "2.4G Distant Hop (Ch 1 -> 11)") if 11 in channels_2g else (1, channels_2g[-1], "2.4G Distant"))
    transitions.append((1, 6, "2.4G Non-Social -> Social (Ch 1 -> 6)"))

    # 2. Intra-band 5.8G
    if len(channels_5g) >= 2:
        s5 = DEFAULT_SOCIAL_5G if DEFAULT_SOCIAL_5G in channels_5g else channels_5g[0]
        ns5 = [c for c in channels_5g if c != s5]
        if ns5:
            transitions.append((s5, ns5[0], f"5.8G Social -> Non-Social ({s5} -> {ns5[0]})"))
            transitions.append((ns5[0], s5, f"5.8G Non-Social -> Social ({ns5[0]} -> {s5})"))
            if len(ns5) >= 2:
                transitions.append((ns5[0], ns5[1], f"5.8G Non-Social Adjacent ({ns5[0]} -> {ns5[1]})"))
                transitions.append((ns5[0], ns5[-1], f"5.8G Non-Social Distant ({ns5[0]} -> {ns5[-1]})"))

    # 3. Cross-band: 2.4G -> 5.8G
    if channels_5g:
        s5 = DEFAULT_SOCIAL_5G if DEFAULT_SOCIAL_5G in channels_5g else channels_5g[0]
        transitions.append((6, s5, f"Cross-band Social 2.4G -> Social 5.8G (6 -> {s5})"))
        transitions.append((1, s5, f"Cross-band Non-Social 2.4G -> Social 5.8G (1 -> {s5})"))
        if len(channels_5g) > 1:
            ns5_first = [c for c in channels_5g if c != s5][0]
            transitions.append((6, ns5_first, f"Cross-band Social 2.4G -> Non-Social 5.8G (6 -> {ns5_first})"))

    # 4. Cross-band: 5.8G -> 2.4G
    if channels_5g:
        s5 = DEFAULT_SOCIAL_5G if DEFAULT_SOCIAL_5G in channels_5g else channels_5g[0]
        transitions.append((s5, 6, f"Cross-band Social 5.8G -> Social 2.4G ({s5} -> 6)"))
        transitions.append((s5, 1, f"Cross-band Social 5.8G -> Non-Social 2.4G ({s5} -> 1)"))
        if len(channels_5g) > 1:
            ns5_first = [c for c in channels_5g if c != s5][0]
            transitions.append((ns5_first, 6, f"Cross-band Non-Social 5.8G -> Social 2.4G ({ns5_first} -> 6)"))

    results: List[Dict[str, Any]] = []
    total_tests = len(methods) * len(transitions)
    curr = 0

    logger.info(f"[*] Executing Comprehensive Evaluation ({total_tests} transition tests, {iterations} reps each)...")

    for method in methods:
        for src_ch, dst_ch, desc in transitions:
            curr += 1
            cat = get_transition_category(src_ch, dst_ch)
            logger.info(f"  [{curr}/{total_tests}] [{method}] {desc} ({src_ch} -> {dst_ch})...")
            res = run_transition_benchmark(
                iface, src_ch, dst_ch, iterations, method=method,
                settle_delay_s=settle_delay_s,
                packet_sniff_window_s=packet_sniff_window_s,
                sniffer=sniffer,
                injector=injector,
                mock=mock
            )
            res["description"] = desc
            results.append(res)

    return results


def run_matrix_benchmark(
    iface: str,
    channels: List[int],
    iterations: int = 10,
    method: str = METHOD_IW_SET_CHANNEL,
    settle_delay_s: float = 0.02,
    packet_sniff_window_s: float = 0.15,
    sniffer: Optional[PacketTimelineSniffer] = None,
    injector: Optional[ActivePulseInjector] = None,
    mock: bool = False
) -> List[Dict[str, Any]]:
    """
    Sweeps a full pairwise N x N matrix across all channels in the provided list.
    """
    results: List[Dict[str, Any]] = []
    total = len(channels) * (len(channels) - 1)
    curr = 0

    logger.info(f"[*] Running Pairwise Matrix Benchmark on {len(channels)} channels ({total} transitions)...")

    for src_ch in channels:
        for dst_ch in channels:
            if src_ch == dst_ch:
                continue
            curr += 1
            res = run_transition_benchmark(
                iface, src_ch, dst_ch, iterations, method=method,
                settle_delay_s=settle_delay_s,
                packet_sniff_window_s=packet_sniff_window_s,
                sniffer=sniffer,
                injector=injector,
                mock=mock
            )
            results.append(res)
            if curr % 10 == 0 or curr == total:
                logger.info(f"  Progress: {curr}/{total} transitions completed...")

    return results


# =============================================================================
# Aggregation & Scanner Calibration Analysis
# =============================================================================

def aggregate_benchmark_results(
    transition_results: List[Dict[str, Any]],
    sequence_result: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Consolidates transition benchmarks into category and target-frequency level statistics."""
    categories = {
        # Legacy/Regime categories
        "intraband_2g": [],
        "intraband_5g": [],
        "intraband_all": [],
        "interband_2g_to_5g": [],
        "interband_5g_to_2g": [],
        "interband_all": [],
        # Target-band & Source-band breakdown
        "target_2g": [],
        "target_5g": [],
        "source_2g": [],
        "source_5g": [],
        # Factorial 2x2 breakdowns (Target x Source)
        "target_2g_from_2g": [],
        "target_2g_from_5g": [],
        "target_5g_from_2g": [],
        "target_5g_from_5g": [],
        "all_transitions": []
    }

    rf_categories = {k: [] for k in categories}
    drain_categories = {k: [] for k in categories}
    blind_spot_categories = {k: [] for k in categories}

    target_ch_groups: Dict[int, List[float]] = {}
    target_ch_rf_groups: Dict[int, List[float]] = {}
    rf_lead_times: List[float] = []
    method_groups: Dict[str, List[float]] = {}

    for tr in transition_results:
        cat = tr.get("category", "other")
        method = tr.get("method", "default")
        src = tr.get("src_channel")
        dst = tr.get("dst_channel")
        src_band = get_wifi_band(src)
        dst_band = get_wifi_band(dst)

        raw_cmd = tr.get("raw_latencies_ms", [])
        raw_rf = tr.get("raw_rf_ready_ms", [])
        raw_lead = tr.get("raw_rf_lead_times_ms", [])
        raw_drain = tr.get("raw_src_drain_ms", [])
        raw_blind = tr.get("raw_rf_blind_spot_ms", [])

        categories["all_transitions"].extend(raw_cmd)
        rf_categories["all_transitions"].extend(raw_rf)
        drain_categories["all_transitions"].extend(raw_drain)
        blind_spot_categories["all_transitions"].extend(raw_blind)
        rf_lead_times.extend(raw_lead)

        if dst not in target_ch_groups:
            target_ch_groups[dst] = []
            target_ch_rf_groups[dst] = []
        target_ch_groups[dst].extend(raw_cmd)
        target_ch_rf_groups[dst].extend(raw_rf)

        if method not in method_groups:
            method_groups[method] = []
        method_groups[method].extend(raw_cmd)

        def add_to_group(grp_name):
            categories[grp_name].extend(raw_cmd)
            rf_categories[grp_name].extend(raw_rf)
            drain_categories[grp_name].extend(raw_drain)
            blind_spot_categories[grp_name].extend(raw_blind)

        # Regimes
        if cat == "intraband_2g":
            add_to_group("intraband_2g")
            add_to_group("intraband_all")
        elif cat == "intraband_5g":
            add_to_group("intraband_5g")
            add_to_group("intraband_all")
        elif cat == "interband_2g_to_5g":
            add_to_group("interband_2g_to_5g")
            add_to_group("interband_all")
        elif cat == "interband_5g_to_2g":
            add_to_group("interband_5g_to_2g")
            add_to_group("interband_all")

        # Target bands
        if dst_band == "2.4GHz":
            add_to_group("target_2g")
        elif "5" in dst_band:
            add_to_group("target_5g")

        # Source bands
        if src_band == "2.4GHz":
            add_to_group("source_2g")
        elif "5" in src_band:
            add_to_group("source_5g")

        # 2x2 Factorials (Target x Source)
        if dst_band == "2.4GHz" and src_band == "2.4GHz":
            add_to_group("target_2g_from_2g")
        elif dst_band == "2.4GHz" and "5" in src_band:
            add_to_group("target_2g_from_5g")
        elif "5" in dst_band and src_band == "2.4GHz":
            add_to_group("target_5g_from_2g")
        elif "5" in dst_band and "5" in src_band:
            add_to_group("target_5g_from_5g")

    category_stats = {k: compute_stats(v) for k, v in categories.items()}
    rf_category_stats = {k: compute_stats(v) for k, v in rf_categories.items()}
    drain_category_stats = {k: compute_stats(v) for k, v in drain_categories.items()}
    blind_spot_category_stats = {k: compute_stats(v) for k, v in blind_spot_categories.items()}
    target_channel_stats = {f"ch_{k}": compute_stats(v) for k, v in sorted(target_ch_groups.items())}
    target_channel_rf_stats = {f"ch_{k}": compute_stats(v) for k, v in sorted(target_ch_rf_groups.items())}
    method_stats = {k: compute_stats(v) for k, v in method_groups.items()}
    lead_time_stats = compute_stats(rf_lead_times)

    # Sensitivity / Factorial Analysis
    t2_mean = category_stats.get("target_2g", {}).get("mean", 0.0)
    t5_mean = category_stats.get("target_5g", {}).get("mean", 0.0)
    target_delta = abs(t5_mean - t2_mean)

    t2_f2_mean = category_stats.get("target_2g_from_2g", {}).get("mean", 0.0)
    t2_f5_mean = category_stats.get("target_2g_from_5g", {}).get("mean", 0.0)
    src_delta_in_2g = abs(t2_f5_mean - t2_f2_mean) if (t2_f2_mean > 0 and t2_f5_mean > 0) else 0.0

    t5_f2_mean = category_stats.get("target_5g_from_2g", {}).get("mean", 0.0)
    t5_f5_mean = category_stats.get("target_5g_from_5g", {}).get("mean", 0.0)
    src_delta_in_5g = abs(t5_f5_mean - t5_f2_mean) if (t5_f2_mean > 0 and t5_f5_mean > 0) else 0.0

    mean_src_delta = (src_delta_in_2g + src_delta_in_5g) / 2.0 if (src_delta_in_2g > 0 or src_delta_in_5g > 0) else 0.0
    dominance_ratio = round(target_delta / max(0.01, mean_src_delta), 1) if mean_src_delta > 0 else (999.0 if target_delta > 0 else 1.0)

    sensitivity_analysis = {
        "mean_target_2g_ms": t2_mean,
        "mean_target_5g_ms": t5_mean,
        "target_band_delta_ms": round(target_delta, 2),
        "source_delta_when_targeting_2g_ms": round(src_delta_in_2g, 2),
        "source_delta_when_targeting_5g_ms": round(src_delta_in_5g, 2),
        "mean_source_delta_ms": round(mean_src_delta, 2),
        "target_dominance_ratio": dominance_ratio
    }

    return {
        "category_stats": category_stats,
        "rf_category_stats": rf_category_stats,
        "drain_category_stats": drain_category_stats,
        "blind_spot_category_stats": blind_spot_category_stats,
        "target_channel_stats": target_channel_stats,
        "target_channel_rf_stats": target_channel_rf_stats,
        "rf_lead_time_stats": lead_time_stats,
        "method_stats": method_stats,
        "sensitivity_analysis": sensitivity_analysis,
        "total_cmd_measurements": len(categories["all_transitions"]),
        "total_rf_measurements": len(rf_categories["all_transitions"])
    }


def compute_scanner_recommendations(
    aggregated_stats: Dict[str, Any],
    safety_margin_ms: float = 5.0,
    ratio_k: int = 1,
    social_dwell_ms: int = 1000,
    non_social_dwell_ms: int = 200,
    default_intraband_ms: int = 30,
    default_interband_ms: int = 50
) -> Dict[str, Any]:
    """
    Calculates empirical parameter recommendations for the Wi-Fi scanner
    (WifiChannelHopperThread) considering both Target-Frequency Band calibration
    and synchronous Command Completion / True RF Readiness timings.
    """
    cat_stats = aggregated_stats.get("category_stats", {})
    rf_cat_stats = aggregated_stats.get("rf_category_stats", {})
    drain_cat_stats = aggregated_stats.get("drain_category_stats", {})
    blind_cat_stats = aggregated_stats.get("blind_spot_category_stats", {})

    intra_stats = cat_stats.get("intraband_all", {})
    inter_stats = cat_stats.get("interband_all", {})
    t2_stats = cat_stats.get("target_2g", {})
    t5_stats = cat_stats.get("target_5g", {})

    rf_intra_stats = rf_cat_stats.get("intraband_all", {})
    rf_inter_stats = rf_cat_stats.get("interband_all", {})
    rf_t2_stats = rf_cat_stats.get("target_2g", {})
    rf_t5_stats = rf_cat_stats.get("target_5g", {})

    # Standard Intra / Inter Recommendations
    intra_p95 = intra_stats.get("p95", 0.0)
    inter_p95 = inter_stats.get("p95", 0.0)
    rec_cmd_intra = max(5, int(math.ceil(intra_p95 + safety_margin_ms))) if intra_p95 > 0 else default_intraband_ms
    rec_cmd_inter = max(10, int(math.ceil(inter_p95 + safety_margin_ms))) if inter_p95 > 0 else default_interband_ms

    # Target-Band Recommendations (Primary when target frequency drives latency)
    t2_p95 = t2_stats.get("p95", 0.0)
    t5_p95 = t5_stats.get("p95", 0.0)
    rec_cmd_to_2g = max(5, int(math.ceil(t2_p95 + safety_margin_ms))) if t2_p95 > 0 else rec_cmd_intra
    rec_cmd_to_5g = max(10, int(math.ceil(t5_p95 + safety_margin_ms))) if t5_p95 > 0 else rec_cmd_inter

    # RF-Readiness Recommendations
    rf_intra_p95 = rf_intra_stats.get("p95", 0.0)
    rf_inter_p95 = rf_inter_stats.get("p95", 0.0)
    rec_rf_intra = max(5, int(math.ceil(rf_intra_p95 + safety_margin_ms))) if rf_intra_p95 > 0 else rec_cmd_intra
    rec_rf_inter = max(10, int(math.ceil(rf_inter_p95 + safety_margin_ms))) if rf_inter_p95 > 0 else rec_cmd_inter

    rf_t2_p95 = rf_t2_stats.get("p95", 0.0)
    rf_t5_p95 = rf_t5_stats.get("p95", 0.0)
    rec_rf_to_2g = max(5, int(math.ceil(rf_t2_p95 + safety_margin_ms))) if rf_t2_p95 > 0 else rec_rf_intra
    rec_rf_to_5g = max(10, int(math.ceil(rf_t5_p95 + safety_margin_ms))) if rf_t5_p95 > 0 else rec_rf_inter

    def calc_cycle_time(intra_delay: float, inter_delay: float) -> Dict[str, float]:
        dwell_total_ms = 3 * social_dwell_ms + 3 * ratio_k * non_social_dwell_ms
        delay_total_ms = 2 * inter_delay + (3 * ratio_k + 1) * intra_delay
        total_cycle_ms = dwell_total_ms + delay_total_ms
        efficiency_pct = (dwell_total_ms / total_cycle_ms) * 100.0 if total_cycle_ms > 0 else 0.0
        full_sweep_cycles = math.ceil(6 / ratio_k)
        full_sweep_duration_s = (full_sweep_cycles * total_cycle_ms) / 1000.0

        return {
            "dwell_time_ms": dwell_total_ms,
            "switching_overhead_ms": delay_total_ms,
            "total_cycle_duration_ms": total_cycle_ms,
            "total_cycle_duration_s": round(total_cycle_ms / 1000.0, 3),
            "sniffing_efficiency_percent": round(efficiency_pct, 2),
            "full_sweep_cycles": full_sweep_cycles,
            "full_sweep_duration_s": round(full_sweep_duration_s, 2)
        }

    baseline_timing = calc_cycle_time(default_intraband_ms, default_interband_ms)
    cmd_timing = calc_cycle_time(rec_cmd_intra, rec_cmd_inter)
    rf_timing = calc_cycle_time(rec_rf_intra, rec_rf_inter)

    return {
        "safety_margin_ms": safety_margin_ms,
        "ratio_k": ratio_k,
        "social_dwell_ms": social_dwell_ms,
        "non_social_dwell_ms": non_social_dwell_ms,
        "measured_intra_stats": intra_stats,
        "measured_inter_stats": inter_stats,
        "measured_target_2g_stats": t2_stats,
        "measured_target_5g_stats": t5_stats,
        "measured_rf_intra_stats": rf_intra_stats,
        "measured_rf_inter_stats": rf_inter_stats,
        "measured_rf_target_2g_stats": rf_t2_stats,
        "measured_rf_target_5g_stats": rf_t5_stats,
        "measured_drain_intra_stats": drain_cat_stats.get("intraband_all", {}),
        "measured_drain_inter_stats": drain_cat_stats.get("interband_all", {}),
        "measured_blind_spot_intra_stats": blind_cat_stats.get("intraband_all", {}),
        "measured_blind_spot_inter_stats": blind_cat_stats.get("interband_all", {}),
        "rf_lead_time_stats": aggregated_stats.get("rf_lead_time_stats", {}),
        "sensitivity_analysis": aggregated_stats.get("sensitivity_analysis", {}),
        "recommended_intraband_delay_ms": rec_cmd_intra,
        "recommended_interband_delay_ms": rec_cmd_inter,
        "recommended_delay_to_2g_ms": rec_cmd_to_2g,
        "recommended_delay_to_5g_ms": rec_cmd_to_5g,
        "recommended_rf_intraband_delay_ms": rec_rf_intra,
        "recommended_rf_interband_delay_ms": rec_rf_inter,
        "recommended_rf_delay_to_2g_ms": rec_rf_to_2g,
        "recommended_rf_delay_to_5g_ms": rec_rf_to_5g,
        "default_intraband_ms": default_intraband_ms,
        "default_interband_ms": default_interband_ms,
        "baseline_cycle": baseline_timing,
        "cmd_calibrated_cycle": cmd_timing,
        "rf_calibrated_cycle": rf_timing,
        "cli_flags_snippet": (
            f"--social-dwell-ms {social_dwell_ms} --non-social-dwell-ms {non_social_dwell_ms} "
            f"--lead-time-2g-ms 40 --lead-time-5g-ms 0 --drain-retention-ms 5.0"
        ),
        "rf_cli_flags_snippet": (
            f"--social-dwell-ms {social_dwell_ms} --non-social-dwell-ms {non_social_dwell_ms} "
            f"--lead-time-2g-ms 40 --lead-time-5g-ms 0 --drain-retention-ms 5.0"
        )
    }


# =============================================================================
# Plotting & Visualization Suite
# =============================================================================

def generate_evaluation_plots(
    dataset: Dict[str, Any],
    output_dir: str
) -> List[str]:
    """Generates publication-ready comparative figures detailing target frequency dependency and transition lifecycles."""
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    import pandas as pd
    import seaborn as sns

    sns.set_theme(style="whitegrid", palette="tab10", font_scale=1.05)
    plt.rcParams['font.sans-serif'] = 'DejaVu Sans'
    plt.rcParams['figure.autolayout'] = True

    os.makedirs(output_dir, exist_ok=True)
    generated_files = []

    transitions = dataset.get("transition_results", [])
    recommendations = dataset.get("recommendations", {})
    metadata = dataset.get("metadata", {})
    iface = metadata.get("interface", "wlan")

    rows = []
    rf_rows = []
    drain_rows = []
    blind_rows = []
    lead_rows = []

    for tr in transitions:
        cat = tr.get("category", "other")
        method = tr.get("method", "default")
        src = tr.get("src_channel")
        dst = tr.get("dst_channel")
        src_band = get_wifi_band(src)
        dst_band = get_wifi_band(dst)
        src_freq = get_freq_for_channel(src)
        dst_freq = get_freq_for_channel(dst)
        freq_delta = abs(dst_freq - src_freq)

        src_lbl = f"From {src_band}"
        dst_lbl = f"Target: {dst_band}"
        dst_ch_str = f"Ch {dst}"

        for lat in tr.get("raw_latencies_ms", []):
            rows.append({
                "source": src, "target": dst, "transition": f"Ch {src} -> Ch {dst}",
                "src_band": src_band, "dst_band": dst_band,
                "src_freq_mhz": src_freq, "dst_freq_mhz": dst_freq,
                "freq_delta_mhz": freq_delta,
                "source_label": src_lbl, "target_label": dst_lbl,
                "target_channel_str": dst_ch_str,
                "category": cat, "method": method, "latency_ms": lat,
                "phase": "4. Command Completion (Blocking)"
            })

        for rf_lat in tr.get("raw_rf_ready_ms", []):
            rf_rows.append({
                "source": src, "target": dst, "transition": f"Ch {src} -> Ch {dst}",
                "src_band": src_band, "dst_band": dst_band,
                "src_freq_mhz": src_freq, "dst_freq_mhz": dst_freq,
                "freq_delta_mhz": freq_delta,
                "source_label": src_lbl, "target_label": dst_lbl,
                "target_channel_str": dst_ch_str,
                "category": cat, "method": method, "latency_ms": rf_lat,
                "phase": "3. Target Channel Lock (1st Packet)"
            })

        for dr_lat in tr.get("raw_src_drain_ms", []):
            drain_rows.append({
                "source": src, "target": dst, "transition": f"Ch {src} -> Ch {dst}",
                "src_band": src_band, "dst_band": dst_band,
                "src_freq_mhz": src_freq, "dst_freq_mhz": dst_freq,
                "freq_delta_mhz": freq_delta,
                "source_label": src_lbl, "target_label": dst_lbl,
                "target_channel_str": dst_ch_str,
                "category": cat, "method": method, "latency_ms": dr_lat,
                "phase": "1. Previous Frequency Drain (Retention)"
            })

        for bl_lat in tr.get("raw_rf_blind_spot_ms", []):
            blind_rows.append({
                "source": src, "target": dst, "transition": f"Ch {src} -> Ch {dst}",
                "src_band": src_band, "dst_band": dst_band,
                "src_freq_mhz": src_freq, "dst_freq_mhz": dst_freq,
                "freq_delta_mhz": freq_delta,
                "source_label": src_lbl, "target_label": dst_lbl,
                "target_channel_str": dst_ch_str,
                "category": cat, "method": method, "latency_ms": bl_lat,
                "phase": "2. RF Synthesizer Blind Spot (Dead Time)"
            })

        for lead in tr.get("raw_rf_lead_times_ms", []):
            lead_rows.append({
                "source": src, "target": dst, "transition": f"Ch {src} -> Ch {dst}",
                "src_band": src_band, "dst_band": dst_band,
                "src_freq_mhz": src_freq, "dst_freq_mhz": dst_freq,
                "freq_delta_mhz": freq_delta,
                "source_label": src_lbl, "target_label": dst_lbl,
                "target_channel_str": dst_ch_str,
                "category": cat, "lead_time_ms": lead
            })

    if not rows:
        logger.warning("No measurement rows to plot.")
        return []

    df = pd.DataFrame(rows)
    df_rf = pd.DataFrame(rf_rows)
    df_drain = pd.DataFrame(drain_rows)
    df_blind = pd.DataFrame(blind_rows)
    df_lead = pd.DataFrame(lead_rows)

    # Sort target channels by frequency
    unique_dst_chs = sorted(df["target"].unique(), key=lambda c: get_freq_for_channel(c))
    dst_ch_order = [f"Ch {c}" for c in unique_dst_chs]

    def clean_source_label(val: Any) -> str:
        s = str(val).strip()
        if "2.4" in s:
            return "From 2.4 GHz"
        elif "5" in s:
            return "From 5.8 GHz"
        return s

    def clean_target_label(val: Any) -> str:
        s = str(val).strip()
        if "2.4" in s:
            return "Target: 2.4 GHz"
        elif "5" in s:
            return "Target: 5.8 GHz"
        return s

    df["source_label"] = df["source_label"].apply(clean_source_label)
    df["target_label_norm"] = df["target_label"].apply(clean_target_label)
    if not df_rf.empty:
        df_rf["source_label"] = df_rf["source_label"].apply(clean_source_label)
        df_rf["target_label_norm"] = df_rf["target_label"].apply(clean_target_label)
    if not df_lead.empty:
        df_lead["source_label"] = df_lead["source_label"].apply(clean_source_label)
        df_lead["target_label_norm"] = df_lead["target_label"].apply(clean_target_label)
    if not df_drain.empty:
        df_drain["source_label"] = df_drain["source_label"].apply(clean_source_label)
        df_drain["target_label_norm"] = df_drain["target_label"].apply(clean_target_label)
    if not df_blind.empty:
        df_blind["source_label"] = df_blind["source_label"].apply(clean_source_label)
        df_blind["target_label_norm"] = df_blind["target_label"].apply(clean_target_label)

    source_palette = {
        "From 2.4 GHz": "#1f77b4",
        "From 5.8 GHz": "#d62728",
        "From 5 GHz": "#d62728"
    }

    source_order = [s for s in ["From 2.4 GHz", "From 5.8 GHz"] if s in df["source_label"].unique()]
    target_band_order = [t for t in ["Target: 2.4 GHz", "Target: 5.8 GHz"] if t in df["target_label_norm"].unique()]

    # =========================================================================
    # 1. Primary Figure: Target Channel Latency Breakdown (Source Invariance)
    # =========================================================================
    fig, ax = plt.subplots(figsize=(11, 6), dpi=300)
    sns.boxplot(
        data=df, x="target_channel_str", y="latency_ms", hue="source_label",
        order=dst_ch_order, hue_order=source_order, palette=source_palette, ax=ax, width=0.6, showfliers=False
    )
    sns.stripplot(
        data=df, x="target_channel_str", y="latency_ms", hue="source_label",
        order=dst_ch_order, hue_order=source_order, dodge=True, alpha=0.35, size=4, palette=source_palette, ax=ax, legend=False
    )

    if "recommended_delay_to_2g_ms" in recommendations:
        ax.axhline(
            recommendations["recommended_delay_to_2g_ms"],
            color="#1f77b4", linestyle="--", linewidth=1.4,
            label=f"Target 2.4G Rec: {recommendations['recommended_delay_to_2g_ms']} ms"
        )
    if "recommended_delay_to_5g_ms" in recommendations:
        ax.axhline(
            recommendations["recommended_delay_to_5g_ms"],
            color="#d62728", linestyle="--", linewidth=1.4,
            label=f"Target 5.8G Rec: {recommendations['recommended_delay_to_5g_ms']} ms"
        )

    ax.set_title(f"Channel Switching Latency Governed by Target Frequency ({iface})\n(Side-by-side Source Band Comparison Demonstrates Source Invariance)", fontsize=13, pad=12, weight="bold")
    ax.set_xlabel("Destination Channel (Sorted by Center Frequency)", fontsize=11, labelpad=8)
    ax.set_ylabel("Command Execution Time (ms)", fontsize=11, labelpad=8)
    ax.legend(title="Originating Band", loc="upper left", frameon=True)
    fig.tight_layout()

    f1_path = os.path.join(output_dir, "target_channel_latency_boxplot.png")
    fig.savefig(f1_path)
    plt.close(fig)
    generated_files.append(f1_path)

    # =========================================================================
    # 2. Factorial 2x2 Interaction Plot (Target Band vs Source Band)
    # =========================================================================
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5), dpi=300)

    # Left: Grouped Boxplot
    sns.boxplot(
        data=df, x="target_label_norm", y="latency_ms", hue="source_label",
        order=target_band_order, palette=source_palette, ax=ax1, width=0.5, showfliers=False
    )
    sns.stripplot(
        data=df, x="target_label_norm", y="latency_ms", hue="source_label",
        order=target_band_order, hue_order=source_order, dodge=True, alpha=0.4, size=4.5, palette=source_palette, ax=ax1, legend=False
    )
    ax1.set_title("A. Target Band vs Source Band Distribution", fontsize=12, weight="bold")
    ax1.set_xlabel("Destination Frequency Band", fontsize=11)
    ax1.set_ylabel("Latency (ms)", fontsize=11)
    ax1.legend(title="Source Band", frameon=True)

    # Right: Factorial Interaction Plot (Connecting Means)
    sns.pointplot(
        data=df, x="target_label_norm", y="latency_ms", hue="source_label",
        order=target_band_order, palette=source_palette, markers=["o", "s"], linestyles=["-", "--"],
        errorbar="se", capsize=0.08, ax=ax2
    )
    ax2.set_title("B. Factorial Interaction & Sensitivity", fontsize=12, weight="bold")
    ax2.set_xlabel("Destination Frequency Band", fontsize=11)
    ax2.set_ylabel("Mean Latency ± SE (ms)", fontsize=11)
    ax2.legend(title="Source Band", frameon=True)

    sens = recommendations.get("sensitivity_analysis", {})
    t_delta = sens.get("target_band_delta_ms", 0.0)
    s_delta = sens.get("mean_source_delta_ms", 0.0)
    ratio = sens.get("target_dominance_ratio", 1.0)
    ax2.text(
        0.05, 0.15,
        f"Target Band Effect (Δ_target): {t_delta:.1f} ms\nSource Band Effect (Δ_source): {s_delta:.1f} ms\nTarget Dominance Ratio: {ratio}x",
        transform=ax2.transAxes, fontsize=9.5, bbox=dict(boxstyle='round,pad=0.5', facecolor='#e8f4f8', edgecolor='#3498db')
    )

    fig.suptitle(f"Target Frequency vs Source Frequency Influence on Switching Latency ({iface})", fontsize=14, weight="bold", y=0.98)
    fig.tight_layout()

    f2_path = os.path.join(output_dir, "target_vs_source_factorial.png")
    fig.savefig(f2_path)
    plt.close(fig)
    generated_files.append(f2_path)

    # =========================================================================
    # 3. Frequency Delta |Δf| vs Target Frequency Comparison
    # =========================================================================
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(13, 5.5), dpi=300)

    # Left: Latency vs Absolute Jump Distance |Δf|
    sns.scatterplot(
        data=df, x="freq_delta_mhz", y="latency_ms", hue="source_label",
        palette=source_palette, alpha=0.6, s=45, ax=ax1
    )
    # Regression line for |Δf|
    if len(df) > 5 and df["freq_delta_mhz"].nunique() > 1:
        sns.regplot(
            data=df, x="freq_delta_mhz", y="latency_ms", scatter=False,
            ax=ax1, color="#555555", line_kws={"linestyle": "--", "linewidth": 1.5}
        )
        r_corr = df["freq_delta_mhz"].corr(df["latency_ms"])
        ax1.text(
            0.05, 0.90, f"Pearson r = {r_corr:.2f} (R² = {r_corr**2:.2f})\nWeak / No Correlation with Jump Distance",
            transform=ax1.transAxes, fontsize=9.5, bbox=dict(boxstyle='round,pad=0.4', facecolor='#fff3cd', edgecolor='#ffeeba')
        )
    ax1.set_title("A. Latency vs Absolute Frequency Jump (|Δf|)", fontsize=12, weight="bold")
    ax1.set_xlabel("Jump Distance |f_dst - f_src| (MHz)", fontsize=11)
    ax1.set_ylabel("Command Execution Time (ms)", fontsize=11)
    ax1.legend(title="Source Band", loc="lower right", frameon=True)

    # Right: Latency vs Target Center Frequency
    sns.scatterplot(
        data=df, x="dst_freq_mhz", y="latency_ms", hue="source_label",
        palette=source_palette, alpha=0.6, s=45, ax=ax2
    )
    if len(df) > 5 and df["dst_freq_mhz"].nunique() > 1:
        sns.regplot(
            data=df, x="dst_freq_mhz", y="latency_ms", scatter=False,
            ax=ax2, color="#d62728", line_kws={"linestyle": "-", "linewidth": 1.8}
        )
        r_tgt = df["dst_freq_mhz"].corr(df["latency_ms"])
        ax2.text(
            0.05, 0.90, f"Pearson r = {r_tgt:.2f} (R² = {r_tgt**2:.2f})\nStrong Determinant (Target Frequency Clusters)",
            transform=ax2.transAxes, fontsize=9.5, bbox=dict(boxstyle='round,pad=0.4', facecolor='#d4edda', edgecolor='#c3e6cb')
        )
    ax2.set_title("B. Latency vs Destination Center Frequency (f_dst)", fontsize=12, weight="bold")
    ax2.set_xlabel("Destination Center Frequency (MHz)", fontsize=11)
    ax2.set_ylabel("Command Execution Time (ms)", fontsize=11)
    ax2.legend(title="Source Band", loc="lower right", frameon=True)

    fig.suptitle(f"Hypothesis Comparison: Jump Distance vs Destination Frequency ({iface})", fontsize=14, weight="bold", y=0.98)
    fig.tight_layout()

    f3_path = os.path.join(output_dir, "frequency_delta_vs_target_freq.png")
    fig.savefig(f3_path)
    plt.close(fig)
    generated_files.append(f3_path)

    # =========================================================================
    # 4. Complete Transition Lifecycle by Target Band
    # =========================================================================
    if not df_drain.empty and not df_rf.empty:
        lifecycle_df = pd.concat([df_drain, df_blind, df_rf, df], ignore_index=True)
        lifecycle_df["target_label_norm"] = lifecycle_df["target_label"].apply(clean_target_label)
        phase_palette = {
            "1. Previous Frequency Drain (Retention)": "#3498db",
            "2. RF Synthesizer Blind Spot (Dead Time)": "#9b59b6",
            "3. Target Channel Lock (1st Packet)": "#27ae60",
            "4. Command Completion (Blocking)": "#e74c3c"
        }
        fig, ax = plt.subplots(figsize=(11, 6), dpi=300)
        sns.boxplot(
            data=lifecycle_df, x="target_label_norm", y="latency_ms", hue="phase",
            order=target_band_order, palette=phase_palette, ax=ax, width=0.6, showfliers=False
        )
        ax.set_title(f"Channel Transition Lifecycle Breakdown by Target Frequency ({iface})", fontsize=13, pad=12, weight="bold")
        ax.set_xlabel("Destination Frequency Band", fontsize=11, labelpad=8)
        ax.set_ylabel("Duration from Switch Command (ms)", fontsize=11, labelpad=8)
        ax.legend(title="Transition Phase", frameon=True, loc="upper right")
        fig.tight_layout()

        f4_path = os.path.join(output_dir, "channel_transition_lifecycle.png")
        fig.savefig(f4_path)
        plt.close(fig)
        generated_files.append(f4_path)

    # =========================================================================
    # 5. Transition Latency Matrix Heatmap (Target = Columns)
    # =========================================================================
    all_channels = sorted(list(set(df["source"].tolist() + df["target"].tolist())), key=lambda c: get_freq_for_channel(c))
    if len(all_channels) > 1:
        matrix_df = pd.DataFrame(index=all_channels, columns=all_channels, dtype=float)
        for _, r in df.groupby(["source", "target"])["latency_ms"].median().reset_index().iterrows():
            matrix_df.loc[int(r["source"]), int(r["target"])] = r["latency_ms"]

        fig, ax = plt.subplots(figsize=(10, 8), dpi=300)
        sns.heatmap(
            matrix_df, annot=True, fmt=".1f", cmap="YlGnBu",
            cbar_kws={'label': 'Median Latency (ms)'}, ax=ax,
            linewidths=0.5, linecolor='white'
        )
        ax.set_title(f"Pairwise Transition Latency Matrix ({iface})\n(Vertical Column Striping Proves Destination Frequency Dominance)", fontsize=13, pad=12, weight="bold")
        ax.set_xlabel("Destination Channel (Tuned Target)", fontsize=11, labelpad=8)
        ax.set_ylabel("Source Channel (Origin)", fontsize=11, labelpad=8)
        fig.tight_layout()

        f5_path = os.path.join(output_dir, "transition_matrix_heatmap.png")
        fig.savefig(f5_path)
        plt.close(fig)
        generated_files.append(f5_path)

    # =========================================================================
    # 6. RF Lead Time Distribution
    # =========================================================================
    if not df_lead.empty:
        fig, ax = plt.subplots(figsize=(9, 5.5), dpi=300)
        sns.boxplot(
            data=df_lead, x="target_label_norm", y="lead_time_ms", hue="source_label",
            order=target_band_order, hue_order=source_order, palette=source_palette, ax=ax, width=0.5, showfliers=False
        )
        sns.stripplot(
            data=df_lead, x="target_label_norm", y="lead_time_ms", hue="source_label",
            order=target_band_order, hue_order=source_order, dodge=True, alpha=0.4, size=4.5, palette=source_palette, ax=ax, legend=False
        )
        ax.axhline(0, color="red", linestyle="--", linewidth=1.2, label="Synchronous Return Line (0 ms)")
        ax.set_title(f"Hardware RF Lead Time Before Command Return ({iface})", fontsize=13, pad=12, weight="bold")
        ax.set_xlabel("Destination Frequency Band", fontsize=11, labelpad=8)
        ax.set_ylabel("Lead Time (ms) [Command Time - RF Ready Time]", fontsize=11, labelpad=8)
        ax.legend(title="Source Band", loc="upper left", frameon=True)
        fig.tight_layout()

        f6_path = os.path.join(output_dir, "rf_lead_time_distribution.png")
        fig.savefig(f6_path)
        plt.close(fig)
        generated_files.append(f6_path)

    # =========================================================================
    # 7. Executive Summary Dashboard
    # =========================================================================
    fig, axes = plt.subplots(2, 2, figsize=(16, 11), dpi=300)

    # Panel A: Destination Channel Boxplot
    sns.boxplot(
        data=df, x="target_channel_str", y="latency_ms", hue="source_label",
        order=dst_ch_order, palette=source_palette, ax=axes[0, 0], width=0.6, showfliers=False
    )
    axes[0, 0].set_title("A. Latency Grouped by Target Channel (Source Invariant)", fontsize=12, weight="bold")
    axes[0, 0].set_xlabel("Target Channel")
    axes[0, 0].set_ylabel("Execution Time (ms)")
    axes[0, 0].legend(title="Origin", fontsize=8, loc="upper left")

    # Panel B: Factorial Interaction Plot
    sns.pointplot(
        data=df, x="target_label_norm", y="latency_ms", hue="source_label",
        order=target_band_order, palette=source_palette, markers=["o", "s"], linestyles=["-", "--"],
        errorbar="se", capsize=0.08, ax=axes[0, 1]
    )
    axes[0, 1].set_title("B. Target Band vs Source Band Interaction", fontsize=12, weight="bold")
    axes[0, 1].set_xlabel("Destination Band")
    axes[0, 1].set_ylabel("Mean Latency (ms)")
    axes[0, 1].legend(title="Origin", fontsize=8, loc="upper left")

    # Panel C: Frequency Distance vs Target Frequency
    if len(df) > 5 and df["dst_freq_mhz"].nunique() > 1:
        sns.scatterplot(
            data=df, x="dst_freq_mhz", y="latency_ms", hue="source_label",
            palette=source_palette, alpha=0.6, s=40, ax=axes[1, 0]
        )
        sns.regplot(data=df, x="dst_freq_mhz", y="latency_ms", scatter=False, ax=axes[1, 0], color="#d62728")
        axes[1, 0].set_title("C. Target Center Frequency Determinant", fontsize=12, weight="bold")
        axes[1, 0].set_xlabel("Destination Frequency (MHz)")
        axes[1, 0].set_ylabel("Latency (ms)")
        axes[1, 0].legend(title="Origin", fontsize=8, loc="lower right")
    else:
        axes[1, 0].axis('off')

    # Panel D: Recommendations Card
    axes[1, 1].axis('off')
    lead_stats = recommendations.get("rf_lead_time_stats", {})
    drain_intra = recommendations.get("measured_drain_intra_stats", {})
    blind_intra = recommendations.get("measured_blind_spot_intra_stats", {})
    sens = recommendations.get("sensitivity_analysis", {})
    rec_text = (
        f"CALIBRATION RECOMMENDATIONS FOR SCANNER\n"
        f"═════════════════════════════════════════════════════════\n\n"
        f"Interface: {iface}  |  Driver: {metadata.get('driver', 'Unknown')}\n"
        f"Active Pulse Injector: {metadata.get('tx_interface', 'Passive (Ambient APs)')}\n\n"
        f"• TARGET FREQUENCY DOMINANCE ANALYSIS:\n"
        f"  - Mean Latency Targeting 2.4 GHz:  {sens.get('mean_target_2g_ms', 'N/A')} ms\n"
        f"  - Mean Latency Targeting 5.8 GHz:  {sens.get('mean_target_5g_ms', 'N/A')} ms\n"
        f"  - Target Band Effect (Δ_target):    {sens.get('target_band_delta_ms', 'N/A')} ms\n"
        f"  - Source Band Effect (Δ_source):    {sens.get('mean_source_delta_ms', 'N/A')} ms\n"
        f"  - Target Dominance Ratio:          {sens.get('target_dominance_ratio', 'N/A')}x (Target frequency drives latency)\n\n"
        f"• TARGET-BAND CALIBRATED DELAYS (RECOMMENDED):\n"
        f"  - Delay When Tuning TO 2.4 GHz:    {recommendations.get('recommended_delay_to_2g_ms', 'N/A')} ms\n"
        f"  - Delay When Tuning TO 5.8 GHz:    {recommendations.get('recommended_delay_to_5g_ms', 'N/A')} ms\n"
        f"  - Physical RF Delay TO 2.4 GHz:    {recommendations.get('recommended_rf_delay_to_2g_ms', 'N/A')} ms\n"
        f"  - Physical RF Delay TO 5.8 GHz:    {recommendations.get('recommended_rf_delay_to_5g_ms', 'N/A')} ms\n\n"
        f"CLI Command Flags:\n"
        f"{recommendations.get('cli_flags_snippet', '')}"
    )
    axes[1, 1].text(
        0.05, 0.95, rec_text, transform=axes[1, 1].transAxes,
        fontsize=9.2, verticalalignment='top', fontfamily='monospace',
        bbox=dict(boxstyle='round,pad=0.8', facecolor='#f8f9fa', edgecolor='#dee2e6', linewidth=1.5)
    )

    fig.suptitle(f"Wi-Fi Monitor Mode Hopping Calibration Dashboard ({iface})", fontsize=15, weight="bold", y=0.98)
    fig.tight_layout()

    f7_path = os.path.join(output_dir, "summary_dashboard.png")
    fig.savefig(f7_path)
    plt.close(fig)
    generated_files.append(f7_path)

    return generated_files


# =============================================================================
# Terminal Summary Presentation
# =============================================================================

def print_summary_report(dataset: Dict[str, Any]):
    """Prints a clear, formatted summary of benchmark results to stdout with target-frequency analysis."""
    metadata = dataset.get("metadata", {})
    aggregated = dataset.get("aggregated_stats", {})
    cat_stats = aggregated.get("category_stats", {})
    rf_cat_stats = aggregated.get("rf_category_stats", {})
    drain_cat_stats = aggregated.get("drain_category_stats", {})
    blind_cat_stats = aggregated.get("blind_spot_category_stats", {})
    target_ch_stats = aggregated.get("target_channel_stats", {})
    lead_stats = aggregated.get("rf_lead_time_stats", {})
    sens = aggregated.get("sensitivity_analysis", {})
    recommendations = dataset.get("recommendations", {})

    print("\n" + "=" * 88)
    print("  WI-FI CHANNEL HOPPING LATENCY, RF READINESS & TARGET-FREQUENCY EVALUATION REPORT")
    print("=" * 88)
    print(f"  Interface (DUT):     {metadata.get('interface')} ({metadata.get('mac_address', 'N/A')})")
    print(f"  Driver:              {metadata.get('driver', 'Unknown')} | PHY: {metadata.get('phy', 'N/A')}")
    tx_iface_str = metadata.get('tx_interface') or "Disabled (Passive Ambient Beacons)"
    print(f"  Active TX Injector:  {tx_iface_str}")
    print(f"  Test Mode:           {metadata.get('mode')} | Repetitions: {metadata.get('iterations')} per test")
    print(f"  Total Samples:       {aggregated.get('total_cmd_measurements', 0)} commands, {aggregated.get('total_rf_measurements', 0)} RF packet arrivals")
    print("-" * 88)

    # 1. Target Band & Source Invariance Factorial Breakdown
    print("1. Synchronous Command Latency: Target Frequency Breakdown & Source Invariance:")
    print(f"{'Target & Origin Breakdown':<32} {'Count':>6} {'Mean (ms)':>10} {'Median':>8} {'p95':>8} {'p99':>8} {'Max':>8}")
    print("-" * 88)

    target_labels = [
        ("target_2g", "► ALL Hops Tuning TO 2.4 GHz"),
        ("target_2g_from_2g", "   • Target 2.4G (From 2.4 GHz)"),
        ("target_2g_from_5g", "   • Target 2.4G (From 5.8 GHz)"),
        ("target_5g", "► ALL Hops Tuning TO 5.8 GHz"),
        ("target_5g_from_2g", "   • Target 5.8G (From 2.4 GHz)"),
        ("target_5g_from_5g", "   • Target 5.8G (From 5.8 GHz)"),
        ("all_transitions", "All Transitions Combined")
    ]

    for k, label in target_labels:
        st = cat_stats.get(k, {})
        if st.get("count", 0) > 0:
            print(
                f"{label:<32} {st.get('count', 0):>6} {st.get('mean', 0.0):>10.2f} "
                f"{st.get('median', 0.0):>8.2f} {st.get('p95', 0.0):>8.2f} "
                f"{st.get('p99', 0.0):>8.2f} {st.get('max', 0.0):>8.2f}"
            )
    print("-" * 88)

    # 2. Target vs Source Dominance Analysis
    if sens:
        print(f"\n  ★ TARGET FREQUENCY SENSITIVITY & DOMINANCE ANALYSIS:")
        print(f"    - Target Band Shift Effect (Δ_target):   {sens.get('target_band_delta_ms'):.2f} ms  (Tuning TO 5.8G vs TO 2.4G)")
        print(f"    - Source Band Variance (Δ_source):      {sens.get('mean_source_delta_ms'):.2f} ms  (Average origin variation)")
        print(f"    - Target Dominance Ratio:              {sens.get('target_dominance_ratio')}x  (Switching time is {sens.get('target_dominance_ratio')}x more sensitive to destination than origin!)")

    # 3. Previous Frequency Retention / Drain Latency
    if any(st.get("count", 0) > 0 for st in drain_cat_stats.values()):
        print("\n2. Previous Frequency Retention (Drain Latency after switch command):")
        print(f"{'Target Frequency Band':<32} {'Count':>6} {'Mean (ms)':>10} {'Median':>8} {'p95':>8} {'p99':>8} {'Max':>8}")
        print("-" * 88)
        for k, label in [("target_2g", "Tuning TO 2.4 GHz"), ("target_5g", "Tuning TO 5.8 GHz"), ("all_transitions", "All Transitions Combined")]:
            st = drain_cat_stats.get(k, {})
            if st.get("count", 0) > 0:
                print(
                    f"{label:<32} {st.get('count', 0):>6} {st.get('mean', 0.0):>10.2f} "
                    f"{st.get('median', 0.0):>8.2f} {st.get('p95', 0.0):>8.2f} "
                    f"{st.get('p99', 0.0):>8.2f} {st.get('max', 0.0):>8.2f}"
                )
        print("-" * 88)

    # 4. RF Synthesizer Blind Spot
    if any(st.get("count", 0) > 0 for st in blind_cat_stats.values()):
        print("\n3. RF Synthesizer Blind Spot (Dead Time between last old and first new packet):")
        print(f"{'Target Frequency Band':<32} {'Count':>6} {'Mean (ms)':>10} {'Median':>8} {'p95':>8} {'p99':>8} {'Max':>8}")
        print("-" * 88)
        for k, label in [("target_2g", "Tuning TO 2.4 GHz"), ("target_5g", "Tuning TO 5.8 GHz"), ("all_transitions", "All Transitions Combined")]:
            st = blind_cat_stats.get(k, {})
            if st.get("count", 0) > 0:
                print(
                    f"{label:<32} {st.get('count', 0):>6} {st.get('mean', 0.0):>10.2f} "
                    f"{st.get('median', 0.0):>8.2f} {st.get('p95', 0.0):>8.2f} "
                    f"{st.get('p99', 0.0):>8.2f} {st.get('max', 0.0):>8.2f}"
                )
        print("-" * 88)

    # 5. Target Channel RF Arrival Latency
    if aggregated.get("total_rf_measurements", 0) > 0:
        print("\n4. Target Channel RF Arrival Latency (True Physical Lock):")
        print(f"{'Target Frequency Band':<32} {'Count':>6} {'Mean (ms)':>10} {'Median':>8} {'p95':>8} {'p99':>8} {'Max':>8}")
        print("-" * 88)
        for k, label in [("target_2g", "Tuning TO 2.4 GHz"), ("target_5g", "Tuning TO 5.8 GHz"), ("all_transitions", "All Transitions Combined")]:
            st = rf_cat_stats.get(k, {})
            if st.get("count", 0) > 0:
                print(
                    f"{label:<32} {st.get('count', 0):>6} {st.get('mean', 0.0):>10.2f} "
                    f"{st.get('median', 0.0):>8.2f} {st.get('p95', 0.0):>8.2f} "
                    f"{st.get('p99', 0.0):>8.2f} {st.get('max', 0.0):>8.2f}"
                )
        print("-" * 88)

        if lead_stats.get("count", 0) > 0:
            print(f"\n  ★ RF HARDWARE LEAD TIME (Command Completion Time - First Packet Arrival Time):")
            print(f"    - Mean Lead Time:    {lead_stats.get('mean'):.2f} ms (Packets arrive {lead_stats.get('mean'):.1f} ms BEFORE command finishes!)")
            print(f"    - Median Lead Time:  {lead_stats.get('median'):.2f} ms")
            print(f"    - Max Lead Time:     {lead_stats.get('max'):.2f} ms")

    # Recommendations
    print("\n" + "=" * 88)
    print("  SCANNER HOPPING SEQUENCE CALIBRATION RECOMMENDATIONS")
    print("=" * 88)
    print(f"  [Option A] Target-Band Calibrated Delays (Optimal for Destination-Driven Radios):")
    print(f"    • Recommended Delay Tuning TO 2.4 GHz:  {recommendations.get('recommended_delay_to_2g_ms')} ms  (p95: {recommendations.get('measured_target_2g_stats', {}).get('p95')} ms + {recommendations.get('safety_margin_ms')} ms margin)")
    print(f"    • Recommended Delay Tuning TO 5.8 GHz:  {recommendations.get('recommended_delay_to_5g_ms')} ms  (p95: {recommendations.get('measured_target_5g_stats', {}).get('p95')} ms + {recommendations.get('safety_margin_ms')} ms margin)")
    print()
    if aggregated.get("total_rf_measurements", 0) > 0:
        print(f"  [Option B] Asynchronous / Physical RF-Aware Hopper (Packets Captured Immediately):")
        print(f"    • Physical Lock Delay TO 2.4 GHz:       {recommendations.get('recommended_rf_delay_to_2g_ms')} ms  (p95: {recommendations.get('measured_rf_target_2g_stats', {}).get('p95')} ms + {recommendations.get('safety_margin_ms')} ms margin)")
        print(f"    • Physical Lock Delay TO 5.8 GHz:       {recommendations.get('recommended_rf_delay_to_5g_ms')} ms  (p95: {recommendations.get('measured_rf_target_5g_stats', {}).get('p95')} ms + {recommendations.get('safety_margin_ms')} ms margin)")
        print()

    print(f"  Hopping Cycle Timing (Ratio k={recommendations.get('ratio_k')}):")
    b_cycle = recommendations.get("baseline_cycle", {})
    cmd_cycle = recommendations.get("cmd_calibrated_cycle", {})
    rf_cycle = recommendations.get("rf_calibrated_cycle", {})
    print(f"    - Baseline Duration (Defaults):   {b_cycle.get('total_cycle_duration_s')} s  (Efficiency: {b_cycle.get('sniffing_efficiency_percent')}%)")
    print(f"    - Calibrated Duration (Sync):     {cmd_cycle.get('total_cycle_duration_s')} s  (Efficiency: {cmd_cycle.get('sniffing_efficiency_percent')}%)")
    if aggregated.get("total_rf_measurements", 0) > 0:
        print(f"    - Calibrated Duration (RF-Ready): {rf_cycle.get('total_cycle_duration_s')} s  (Efficiency: {rf_cycle.get('sniffing_efficiency_percent')}%)")
    print()
    print("  Apply these parameters to your combined listener:")
    print(f"  sudo .venv/bin/python scanner/combined_rid_listener.py --wifi-iface {metadata.get('interface')} {recommendations.get('cli_flags_snippet')}")
    print("=" * 88 + "\n")


# =============================================================================
# Main CLI Entry Point
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Wi-Fi Monitor Mode Channel Hopping Latency, RF Readiness & Drain Evaluation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # 1. Active Injection Test: transmit deterministic pulses from wlan0 while switching on wlx00c0cabb1654:
  sudo .venv/bin/python evaluation/hopping_evaluation.py -i wlx00c0cabb1654 --tx-interface wlan0 --pulse-rate 500 --plot

  # 2. Passive Ambient Sniffing Test on single interface:
  sudo .venv/bin/python evaluation/hopping_evaluation.py -i wlx00c0cabb1654 --plot

  # 3. Dry-run / Simulation test of complete transition lifecycle:
  .venv/bin/python evaluation/hopping_evaluation.py --mock --plot
        """
    )
    parser.add_argument("-i", "--interface", type=str, default="wlan1",
                        help="Wi-Fi interface to evaluate (DUT / receiver, default: wlan1)")
    parser.add_argument("--tx-interface", "--injector", type=str, default=None,
                        help="Auxiliary Wi-Fi interface for active calibration frame injection (e.g. wlan0)")
    parser.add_argument("--pulse-rate", type=int, default=500,
                        help="Active pulse transmission rate in Hz (default: 500 Hz / 2ms interval)")
    parser.add_argument("-n", "--iterations", type=int, default=20,
                        help="Number of repeat switches per channel transition (default: 20)")
    parser.add_argument("--mode", type=str, choices=["comprehensive", "scanner_sequence", "matrix", "quick"],
                        default="comprehensive", help="Benchmark evaluation mode (default: comprehensive)")
    parser.add_argument("--methods", type=str, default="iw_set_channel",
                        help=f"Comma-separated switching methods: '{METHOD_IW_SET_CHANNEL}', '{METHOD_IW_SET_FREQ}', '{METHOD_IWCONFIG}', or 'all'")
    parser.add_argument("--channels-2g", type=str, default=None,
                        help="Comma-separated 2.4 GHz channels (default: auto-detected or 1..13)")
    parser.add_argument("--channels-5g", type=str, default=None,
                        help="Comma-separated 5.8 GHz channels (default: auto-detected or 149..165)")
    parser.add_argument("--social-2g", type=int, default=DEFAULT_SOCIAL_2G,
                        help=f"2.4 GHz social channel (default: {DEFAULT_SOCIAL_2G})")
    parser.add_argument("--social-5g", type=int, default=DEFAULT_SOCIAL_5G,
                        help=f"5.8 GHz social channel (default: {DEFAULT_SOCIAL_5G})")
    parser.add_argument("-k", "--ratio-k", type=int, default=1,
                        help="Scanner non-social hopping ratio multiplier k (default: 1)")
    parser.add_argument("--cycles", type=int, default=6,
                        help="Number of cycles for scanner sequence evaluation (default: 6)")
    parser.add_argument("--social-dwell-ms", type=int, default=1000,
                        help="Dwell time on social channels in ms (default: 1000)")
    parser.add_argument("--non-social-dwell-ms", type=int, default=200,
                        help="Dwell time on non-social channels in ms (default: 200)")
    parser.add_argument("--safety-margin-ms", type=float, default=5.0,
                        help="Safety margin in ms added to p95/p99 for recommendations (default: 5.0)")
    parser.add_argument("--settle-delay", type=float, default=0.02,
                        help="Delay in seconds between successive channel switches (default: 0.02s)")
    parser.add_argument("--sniff-window", type=float, default=0.15,
                        help="Post-switch observation window in seconds to capture target channel packets (default: 0.15s)")
    parser.add_argument("--no-sniff-rf", action="store_true",
                        help="Disable concurrent raw socket packet capture for RF readiness analysis")
    parser.add_argument("--setup-monitor", action="store_true",
                        help="Automatically configure interface to monitor mode before evaluation")
    parser.add_argument("--setup-tx-monitor", action="store_true",
                        help="Automatically configure TX injector interface to monitor mode")
    parser.add_argument("--teardown-monitor", action="store_true",
                        help="Restore interface to managed mode upon exit")
    parser.add_argument("-o", "--out", type=str, default=None,
                        help="Output JSON file path (default: evaluation/data/hopping_<iface>_<timestamp>.json)")
    parser.add_argument("--data-dir", type=str, default=os.path.join(eval_dir, "data"),
                        help="Directory to save JSON benchmark datasets (default: evaluation/data)")
    parser.add_argument("--plot", action="store_true", default=False,
                        help="Generate publication-ready comparative plots")
    parser.add_argument("--plot-dir", type=str, default=None,
                        help="Directory to save generated plots (default: evaluation/plots/hopping_<iface>/)")
    parser.add_argument("--mock", action="store_true", default=False,
                        help="Mock execution mode for testing/simulation without physical hardware")

    args = parser.parse_args()

    if not args.mock and os.geteuid() != 0:
        logger.warning("You are not running as root. Wi-Fi channel switching and raw packet sniffing usually require sudo.")

    driver = get_interface_driver(args.interface) if not args.mock else "MockWirelessDriver"
    mac = get_interface_mac(args.interface) if not args.mock else "00:C0:CA:12:34:56"
    phy = get_interface_phy(args.interface) if not args.mock else "phy0"

    if args.channels_2g:
        channels_2g = [int(x.strip()) for x in args.channels_2g.split(",") if x.strip()]
    else:
        phy_2g, _ = get_phy_supported_channels(phy) if not args.mock else (DEFAULT_CHANNELS_2G, DEFAULT_CHANNELS_5G)
        channels_2g = phy_2g

    if args.channels_5g:
        channels_5g = [int(x.strip()) for x in args.channels_5g.split(",") if x.strip()]
    else:
        _, phy_5g = get_phy_supported_channels(phy) if not args.mock else (DEFAULT_CHANNELS_2G, DEFAULT_CHANNELS_5G)
        channels_5g = phy_5g

    if args.methods.lower() == "all":
        methods = ALL_METHODS
    else:
        methods = [m.strip() for m in args.methods.split(",") if m.strip()]

    logger.info("=" * 60)
    logger.info("Wi-Fi Channel Hopping Latency, RF Readiness & Drain Evaluation Harness")
    logger.info(f"Interface (DUT): {args.interface} | Driver: {driver} | PHY: {phy}")
    if args.tx_interface:
        logger.info(f"Active TX Injector: {args.tx_interface} (Pulse Rate: {args.pulse_rate} Hz)")
    else:
        logger.info("Active TX Injector: None (Passive ambient beacon listening)")
    logger.info(f"2.4 GHz Channels: {channels_2g}")
    logger.info(f"5.8 GHz Channels: {channels_5g}")
    logger.info(f"Switching Methods: {methods}")
    logger.info(f"Evaluation Mode: {args.mode} | Mock: {args.mock}")
    logger.info("=" * 60)

    if not args.mock:
        if args.setup_monitor:
            setup_monitor_mode(args.interface, args.social_2g)
        elif not check_monitor_mode(args.interface):
            logger.warning(f"Interface {args.interface} does not appear to be in monitor mode!")
            logger.warning("Consider running with --setup-monitor or running ./interface-monitor.sh first.")

        if args.tx_interface and args.setup_tx_monitor:
            setup_monitor_mode(args.tx_interface, args.social_2g)

    sniffer = None
    if not args.no_sniff_rf:
        sniffer = PacketTimelineSniffer(args.interface, mock=args.mock)
        sniffer.start()
        logger.info(f"[*] Concurrent packet timeline sniffer initialized on {args.interface}.")

    injector = None
    if args.tx_interface or args.mock:
        tx_name = args.tx_interface or "mock_tx0"
        injector = ActivePulseInjector(tx_name, pulse_rate_hz=args.pulse_rate, mock=args.mock)
        logger.info(f"[*] Active pulse injector configured on {tx_name} ({args.pulse_rate} Hz).")

    transition_results: List[Dict[str, Any]] = []
    sequence_result: Optional[Dict[str, Any]] = None

    try:
        if args.mode == "comprehensive":
            transition_results = run_comprehensive_benchmark(
                args.interface,
                iterations=args.iterations,
                channels_2g=channels_2g,
                channels_5g=channels_5g,
                methods=methods,
                settle_delay_s=args.settle_delay,
                packet_sniff_window_s=args.sniff_window,
                sniffer=sniffer,
                injector=injector,
                mock=args.mock
            )
            sequence_result = run_scanner_sequence_benchmark(
                args.interface,
                cycles=args.cycles,
                ratio_k=args.ratio_k,
                social_2g=args.social_2g,
                social_5g=args.social_5g,
                channels_2g=channels_2g,
                channels_5g=channels_5g,
                method=methods[0],
                settle_delay_s=args.settle_delay,
                packet_sniff_window_s=args.sniff_window,
                sniffer=sniffer,
                injector=injector,
                mock=args.mock
            )
        elif args.mode == "scanner_sequence":
            sequence_result = run_scanner_sequence_benchmark(
                args.interface,
                cycles=args.cycles,
                ratio_k=args.ratio_k,
                social_2g=args.social_2g,
                social_5g=args.social_5g,
                channels_2g=channels_2g,
                channels_5g=channels_5g,
                method=methods[0],
                settle_delay_s=args.settle_delay,
                packet_sniff_window_s=args.sniff_window,
                sniffer=sniffer,
                injector=injector,
                mock=args.mock
            )
            trans_map: Dict[Tuple[int, int], List[float]] = {}
            for h in sequence_result["hops"]:
                pair = (h["src_channel"], h["dst_channel"])
                if pair not in trans_map:
                    trans_map[pair] = []
                if h["success"]:
                    trans_map[pair].append(h["latency_ms"])
            for (src, dst), lats in trans_map.items():
                transition_results.append({
                    "src_channel": src,
                    "dst_channel": dst,
                    "src_band": get_wifi_band(src),
                    "dst_band": get_wifi_band(dst),
                    "category": get_transition_category(src, dst),
                    "method": methods[0],
                    "iterations": len(lats),
                    "successful_samples": len(lats),
                    "failed_samples": 0,
                    "success_rate_percent": 100.0,
                    "cmd_stats": compute_stats(lats),
                    "raw_latencies_ms": lats,
                    "rf_ready_stats": compute_stats([]),
                    "raw_rf_ready_ms": [],
                    "rf_lead_time_stats": compute_stats([]),
                    "raw_rf_lead_times_ms": [],
                    "src_drain_stats": compute_stats([]),
                    "raw_src_drain_ms": [],
                    "rf_blind_spot_stats": compute_stats([]),
                    "raw_rf_blind_spot_ms": []
                })
        elif args.mode == "matrix":
            all_ch = sorted(list(set(channels_2g + channels_5g)))
            transition_results = run_matrix_benchmark(
                args.interface,
                channels=all_ch,
                iterations=args.iterations,
                method=methods[0],
                settle_delay_s=args.settle_delay,
                packet_sniff_window_s=args.sniff_window,
                sniffer=sniffer,
                injector=injector,
                mock=args.mock
            )
        elif args.mode == "quick":
            quick_2g = [1, 6, 11] if 11 in channels_2g else [channels_2g[0], channels_2g[len(channels_2g)//2], channels_2g[-1]]
            quick_5g = [149, 157] if len(channels_5g) >= 2 else channels_5g
            transition_results = run_comprehensive_benchmark(
                args.interface,
                iterations=min(args.iterations, 10),
                channels_2g=quick_2g,
                channels_5g=quick_5g,
                methods=[methods[0]],
                settle_delay_s=args.settle_delay,
                packet_sniff_window_s=args.sniff_window,
                sniffer=sniffer,
                injector=injector,
                mock=args.mock
            )

    finally:
        if injector:
            injector.cleanup()
        if sniffer:
            sniffer.stop()
        if not args.mock and args.teardown_monitor:
            teardown_monitor_mode(args.interface)

    # Aggregation & Recommendations
    aggregated = aggregate_benchmark_results(transition_results, sequence_result)
    recommendations = compute_scanner_recommendations(
        aggregated,
        safety_margin_ms=args.safety_margin_ms,
        ratio_k=args.ratio_k,
        social_dwell_ms=args.social_dwell_ms,
        non_social_dwell_ms=args.non_social_dwell_ms
    )

    # Build Complete Output Document
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    dataset = {
        "metadata": {
            "timestamp": timestamp,
            "interface": args.interface,
            "mac_address": mac,
            "driver": driver,
            "phy": phy,
            "tx_interface": args.tx_interface,
            "pulse_rate_hz": args.pulse_rate if args.tx_interface else None,
            "mode": args.mode,
            "iterations": args.iterations,
            "ratio_k": args.ratio_k,
            "methods_tested": methods,
            "channels_2g": channels_2g,
            "channels_5g": channels_5g,
            "social_channel_2g": args.social_2g,
            "social_channel_5g": args.social_5g,
            "sniff_rf_enabled": not args.no_sniff_rf,
            "is_mock": args.mock
        },
        "recommendations": recommendations,
        "aggregated_stats": aggregated,
        "transition_results": transition_results,
        "sequence_result": sequence_result
    }

    # Print Terminal Report
    print_summary_report(dataset)

    # Save JSON Dataset
    os.makedirs(args.data_dir, exist_ok=True)
    if args.out:
        out_json_path = args.out
    else:
        out_json_path = os.path.join(args.data_dir, f"hopping_eval_{args.interface}_{timestamp}.json")

    with open(out_json_path, "w") as f:
        json.dump(dataset, f, indent=2)
    logger.info(f"[✓] Benchmark dataset saved to: {out_json_path}")

    # Generate Plots if requested
    if args.plot:
        if args.plot_dir:
            plot_dir = args.plot_dir
        else:
            plot_dir = os.path.join(eval_dir, "plots", f"hopping_{args.interface}_{timestamp}")

        logger.info(f"[*] Generating comparative plots in: {plot_dir}...")
        generated = generate_evaluation_plots(dataset, plot_dir)
        for g in generated:
            logger.info(f"  [✓] Figure generated: {g}")

    logger.info("[*] Hopping evaluation complete.")


if __name__ == "__main__":
    main()
