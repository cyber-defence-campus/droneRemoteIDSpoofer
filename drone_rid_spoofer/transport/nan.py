"""NAN (Wi-Fi Aware) transport backends supporting both an Android App TCP bridge and direct Linux raw packet injection."""

import base64
import hashlib
import json
import logging
import random
import socket
import subprocess
import threading
import time
from typing import List, Dict, Optional

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import MsgType
from drone_rid_spoofer.transport.base import TransportBackend

logger = logging.getLogger(__name__)


class NanBridgeBackend(TransportBackend):
    """NAN (Wi-Fi Aware) transport for ASTM F3411-22 RID using Android TCP bridge.
    
    Connects to a bridge Android App over a TCP connection (via ADB port forwarding)
    and sends JSON commands to manage Wi-Fi Aware publish sessions.
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 8080, protocol_version: int = 2, update_interval: float = 1.0, fuzz_config: dict = None):
        super().__init__(fuzz_config)
        self.host = host
        self.port = port
        self.protocol_version = protocol_version
        self.update_interval = update_interval
        self.sock = None
        self.lock = threading.Lock()
        self._configured_drones = set()
        self._counters = {}
        self._stop_event = threading.Event()
        self._listener_thread = None
        self._drones = []
        self._packet_builder = None
        self._transmit_thread = None
        self._connect()

    def start(self, drones: List[DroneState], packet_builder) -> None:
        self._drones = drones
        self._packet_builder = packet_builder
        self._transmit_thread = threading.Thread(target=self._transmit_loop, daemon=True)
        self._transmit_thread.start()
        logging.info(f"NAN backend background thread started with {self.update_interval}s interval")

    def _listen(self, sock):
        """Listen for incoming messages from the Android bridge."""
        sock.settimeout(1.0)
        try:
            # makefile makes reading lines easy
            with sock.makefile('r', encoding='utf-8') as f:
                while not self._stop_event.is_set():
                    try:
                        line = f.readline()
                        if not line:
                            break
                        msg = json.loads(line)
                        if msg.get("type") == "ERROR":
                            logging.error(f"NAN Bridge Error for drone {msg.get('drone_id')}: {msg.get('reason')}")
                    except socket.timeout:
                        continue
                    except json.JSONDecodeError:
                        pass
        except Exception:
            pass

    def _connect(self):
        """Establish TCP connection to the Android App."""
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(5.0)
            self.sock.connect((self.host, self.port))
            logging.info(f"Connected to NAN bridge at {self.host}:{self.port}")
            self._listener_thread = threading.Thread(target=self._listen, args=(self.sock,), daemon=True)
            self._listener_thread.start()
        except Exception as e:
            logging.error(f"Failed to connect to NAN bridge at {self.host}:{self.port}: {e}")
            self.sock = None

    def _send_command(self, cmd: dict):
        """Send JSON command over TCP."""
        with self.lock:
            if not self.sock:
                # Attempt to reconnect
                self._connect()
                if not self.sock:
                    return

            try:
                data = json.dumps(cmd) + "\n"
                self.sock.sendall(data.encode('utf-8'))
            except Exception as e:
                logging.error(f"Error sending command to NAN bridge: {e}")
                self.sock.close()
                self.sock = None

    def send_raw(self, drone_key: str, payload: bytes) -> None:
        """Send a raw byte payload via NAN."""
        if drone_key not in self._configured_drones:
            config_cmd = {
                "type": "CONFIG",
                "drone_id": drone_key
            }
            self._send_command(config_cmd)
            self._configured_drones.add(drone_key)

        if len(payload) > 255:
            logging.warning(f"NAN Raw Payload too large ({len(payload)} bytes). Truncating to 255.")
            payload = payload[:255]

        payload_b64 = base64.b64encode(payload).decode('ascii')
        payload_cmd = {
            "type": "PAYLOAD",
            "drone_id": drone_key,
            "payload": payload_b64
        }
        self._send_command(payload_cmd)

    def _transmit_loop(self) -> None:
        import time
        # Wait until drones are populated
        while not self._stop_event.is_set() and not self._drones:
            time.sleep(0.01)
            
        next_tick = time.time()
        while not self._stop_event.is_set():
            for drone in self._drones:
                if not getattr(drone, 'active', True):
                    continue
                
                # Initialize the drone on the Android bridge if not already done
                if drone.mac_address not in self._configured_drones:
                    config_cmd = {
                        "type": "CONFIG",
                        "drone_id": drone.mac_address
                    }
                    self._send_command(config_cmd)
                    self._configured_drones.add(drone.mac_address)

                messages = self._packet_builder(drone)
                drone_key = drone.mac_address
                
                if hasattr(drone, 'counter_override') and drone.counter_override is not None:
                    counter = drone.counter_override
                else:
                    counter = self._counters.get(drone_key, 0)
                    self._counters[drone_key] = (counter + 1) & 0xFF
                
                pack_type_ver = self.fuzz_config.get("pack_type_ver", (MsgType.PACK << 4) | self.protocol_version)
                pack_msg_size = self.fuzz_config.get("pack_msg_size", 0x19)
                msg_count = self.fuzz_config.get("pack_msg_count", len(messages) & 0xFF)
                pack_header = bytes([counter, pack_type_ver & 0xFF, pack_msg_size & 0xFF, msg_count & 0xFF])

                payload = pack_header + b''.join(messages)
                if len(payload) > 255 and not self.fuzz_config.get("disable_pack_limit", False):
                    logging.warning(f"NAN Payload too large ({len(payload)} bytes). Truncating to 255.")
                    payload = payload[:255]

                payload_b64 = base64.b64encode(payload).decode('ascii')
                payload_cmd = {
                    "type": "PAYLOAD",
                    "drone_id": drone.mac_address,
                    "payload": payload_b64
                }
                self._send_command(payload_cmd)
                
            next_tick += self.update_interval
            now = time.time()
            if next_tick < now:
                next_tick = now
                
            sleep_time = next_tick - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

    def remove_drone(self, drone: DroneState) -> None:
        """Stop publishing and remove state for an expired drone."""
        if drone.mac_address in self._configured_drones:
            stop_cmd = {
                "type": "STOP",
                "drone_id": drone.mac_address
            }
            self._send_command(stop_cmd)
            self._configured_drones.discard(drone.mac_address)
        self._counters.pop(drone.mac_address, None)

    def close(self) -> None:
        """Close the connection to the Android bridge."""
        self._stop_event.set()
        if self.sock:
            with self.lock:
                # Tell Android to stop all publishing
                try:
                    cmd = {"type": "STOP_ALL"}
                    data = json.dumps(cmd) + "\n"
                    self.sock.sendall(data.encode('utf-8'))
                except Exception:
                    pass
                self._configured_drones.clear()
                
                try:
                    self.sock.close()
                except Exception:
                    pass
                self.sock = None
            logging.info("Disconnected from NAN bridge.")
        if self._listener_thread:
            self._listener_thread.join(timeout=2.0)
        if self._transmit_thread:
            self._transmit_thread.join(timeout=2.0)

    def reset(self) -> None:
        """Perform a full system reset of the Android NAN subsystem."""
        if self.sock:
            with self.lock:
                try:
                    cmd = {"type": "RESET"}
                    data = json.dumps(cmd) + "\n"
                    self.sock.sendall(data.encode('utf-8'))
                except Exception as e:
                    logging.error(f"Failed to send RESET command: {e}")
                self._configured_drones.clear()
            logging.info("Sent RESET command to NAN bridge.")


# Maintain backward compatibility alias for scripts relying on NanBackend
NanBackend = NanBridgeBackend


class NanManualBackend(TransportBackend):
    """NAN (Wi-Fi Aware) manual userspace packet injection backend.

    Binds a raw AF_PACKET L2 socket to a monitor mode interface and injects
    standards-compliant IEEE 802.11 NAN frames directly, implementing dual-beacon
    synchronization and dynamic Service Discovery Frames (SDF) without external hardware.
    """

    NAN_SERVICE_NAME = b"org.opendroneid.remoteid"
    DEFAULT_CLUSTER_ID = "50:6f:9a:01:00:00"

    def __init__(
        self,
        interface: str,
        protocol_version: int = 2,
        channel: int = 6,
        cluster_id: str = DEFAULT_CLUSTER_ID,
        instance_id: int = 0x10,
        rate_mbps: float = 1.0,
        update_interval: float = 1.0,
        fuzz_config: Optional[dict] = None,
    ):
        super().__init__(fuzz_config)
        self.interface = interface
        self.protocol_version = protocol_version
        self.channel = channel
        self.cluster_id_str = cluster_id
        self.instance_id = instance_id & 0xFF
        self.rate_mbps = rate_mbps
        self.update_interval = update_interval

        self.cluster_bssid = bytes.fromhex(self.cluster_id_str.replace(":", ""))
        if len(self.cluster_bssid) != 6:
            logger.warning(f"Invalid cluster ID format {self.cluster_id_str}, falling back to default 50:6f:9a:01:00:00")
            self.cluster_bssid = bytes.fromhex("506f9a010000")

        self.service_id_hash = hashlib.sha256(self.NAN_SERVICE_NAME).digest()[:6]

        # Lock the physical interface to the target Wi-Fi channel
        try:
            subprocess.run(
                ["sudo", "iw", "dev", self.interface, "set", "channel", str(self.channel)],
                check=True
            )
            logger.info(f"NAN Manual: Wi-Fi interface {self.interface} locked to channel {self.channel}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Could not lock channel on {self.interface}: {e}")

        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self._sock.bind((self.interface, 0))
            logger.info(f"Raw AF_PACKET socket created on {self.interface} for NAN manual injection")
        except Exception as e:
            logger.error(f"Failed to create raw socket on {self.interface}. Needs sudo? {e}")
            raise

        # Precompute Radiotap header
        rate_500kbps = int(self.rate_mbps * 2)
        try:
            from scapy.all import RadioTap
            self.radiotap_bytes = bytes(RadioTap(present="Rate", Rate=rate_500kbps))
        except Exception:
            # Fallback 8-byte minimal RadioTap header if Scapy instantiation fails or module missing
            self.radiotap_bytes = b"\x00\x00\x08\x00\x00\x00\x00\x00"

        self._seq_nums: Dict[bytes, int] = {}
        self._msg_counters: Dict[bytes, int] = {}
        self._running = False
        self._drones: List[DroneState] = []
        self._packet_builder = None
        self._thread: Optional[threading.Thread] = None
        self.missed_deadlines = 0

        logger.info(
            f"NanManualBackend initialized on {self.interface} | Cluster: {self.cluster_id_str} | Instance ID: 0x{self.instance_id:02X}"
        )

    def start(self, drones: List[DroneState], packet_builder) -> None:
        self._drones = drones
        self._packet_builder = packet_builder
        self._running = True
        self._thread = threading.Thread(target=self._transmit_loop, daemon=True)
        self._thread.start()
        logger.info("NanManualBackend transmission thread started")

    def _mac_str_to_bytes(self, mac_str: str) -> bytes:
        try:
            return bytes.fromhex(mac_str.replace(":", ""))
        except Exception:
            return b"\x02\x11\x22\x33\x44\x55"

    def _build_nan_beacon(
        self,
        drone_mac: bytes,
        is_sync: bool,
        seq_num: int,
        tsf_us: int,
        ambtt_us: int
    ) -> bytes:
        """Construct raw IEEE 802.11 NAN Cluster Beacon frame."""
        # 1. 802.11 MAC Header (24 bytes)
        fc_duration = b"\x80\x00\x00\x00"  # Beacon, Type 0 Subtype 8, duration 0
        dest_addr = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = (seq_num << 4).to_bytes(2, "little")
        mac_header = fc_duration + dest_addr + drone_mac + self.cluster_bssid + seq_ctrl

        # 2. Fixed Parameters (12 bytes)
        timestamp_bytes = tsf_us.to_bytes(8, "little", signed=False)
        beacon_interval_tu = 512 if is_sync else 100
        beacon_interval_bytes = beacon_interval_tu.to_bytes(2, "little")
        capabilities = b"\x20\x06"  # 0x0620 NAN anchor capabilities
        fixed_params = timestamp_bytes + beacon_interval_bytes + capabilities

        # 3. Wi-Fi Aware Vendor Specific IE (OUI 50:6F:9A, Type 0x13)
        # Master Indication Attribute (Attr ID 0, length 2, Pref 254, Random 0xDF)
        master_ind = b"\x00\x02\x00\xfe\xdf"

        # NAN Cluster Attribute (Attr ID 1, length 13)
        ambtt_bytes = (ambtt_us & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        nan_cluster_attr = b"\x01\x0d\x00" + drone_mac + b"\xdf\xfe\x00" + ambtt_bytes

        # Country Code Attribute (Attr ID 11, length 2, "CH")
        country_code = b"\x0b\x02\x00CH"

        # Device Capability Attribute (Attr ID 15, length 9)
        device_cap = b"\x0f\x09\x00\x00\x49\x08\x14\x01\x22\x58\x1b\x08"

        # Service ID List Attribute (Attr ID 2, length 6)
        service_id_attr = b"\x02\x06\x00" + self.service_id_hash

        # Vendor Specific NAN Attribute & Envelope Tail (17 bytes)
        vendor_nan_tail = b"\xdd\x0e\x00\x00\x00\xf0\x33\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00"

        wfa_payload = b"\x50\x6f\x9a\x13" + master_ind + nan_cluster_attr + country_code + device_cap + service_id_attr + vendor_nan_tail
        ie_wfa = b"\xdd" + len(wfa_payload).to_bytes(1, "little") + wfa_payload

        return self.radiotap_bytes + mac_header + fixed_params + ie_wfa

    def _build_nan_sdf(
        self,
        drone: DroneState,
        drone_mac: bytes,
        messages: List[bytes],
        counter: int,
        seq_num: int
    ) -> bytes:
        """Construct raw NAN Service Discovery Frame (SDF) with dynamic SDEA Service Update Indicator."""
        # 1. 802.11 MAC Header (24 bytes) - Action Frame (Subtype 13)
        fc_duration = b"\xd0\x00\x00\x00"
        dest_addr = b"\xff\xff\xff\xff\xff\xff"
        seq_ctrl = (seq_num << 4).to_bytes(2, "little")
        mac_header = fc_duration + dest_addr + drone_mac + self.cluster_bssid + seq_ctrl

        # 2. Public Action Frame Header (6 bytes)
        action_header = b"\x04\x09\x50\x6f\x9a\x13"

        # 3. Service Descriptor Attribute (SDA) - Attr ID 3, len 139
        pack_type_ver = self.fuzz_config.get("pack_type_ver", (MsgType.PACK << 4) | self.protocol_version) if self.fuzz_config else ((MsgType.PACK << 4) | self.protocol_version)
        pack_msg_size = self.fuzz_config.get("pack_msg_size", 0x19) if self.fuzz_config else 0x19
        msg_count = len(messages) & 0xFF
        if self.fuzz_config and "pack_msg_count" in self.fuzz_config:
            msg_count = self.fuzz_config["pack_msg_count"]

        pack_header = bytes([counter & 0xFF, pack_type_ver & 0xFF, pack_msg_size & 0xFF, msg_count & 0xFF])
        raw_msgs = b"".join(messages)[:125]
        if len(raw_msgs) < 125:
            raw_msgs += b"\x00" * (125 - len(raw_msgs))
        service_info = pack_header + raw_msgs

        sda_header = (
            b"\x03\x8b\x00"
            + self.service_id_hash
            + bytes([self.instance_id, 0x00, 0x10, len(service_info) & 0xFF])
        )
        sda_attr = sda_header + service_info

        # 4. Service Descriptor Extension Attribute (SDEA) - Attr ID 14 (0x0E), len 4
        # Service Update Indicator equals ODID counter to defeat receiver OS frame deduplication
        sdea_attr = b"\x0e\x04\x00" + bytes([self.instance_id, 0x00, 0x02, counter & 0xFF])

        # 5. Additional mandatory NAN attributes
        country_code = b"\x0b\x02\x00CH"
        device_cap = b"\x0f\x09\x00\x00\x49\x08\x14\x01\x22\x58\x1b\x08"
        avail_1 = b"\x12\x13\x00\x00\x31\x00\x0e\x00\xea\x12\x18\x00\x04\xfe\xfe\xff\xff\x11\x51\xff\x1f\x00"
        avail_2 = b"\x12\x23\x00\x00\x32\x00\x0e\x00\xf2\x12\x18\x00\x04\x00\xfe\x00\xff\x11\x80\x21\x00\x0f\x0e\x00\xf2\x12\x18\x00\x04\xff\x00\xff\x00\x11\x80\x01\x00\x01"
        vendor_nan = b"\xdd\x0e\x00\x00\x00\xf0\x33\x08\x00\x01\x00\x00\x00\x00\x00\x00\x00"

        return self.radiotap_bytes + mac_header + action_header + sda_attr + sdea_attr + country_code + device_cap + avail_1 + avail_2 + vendor_nan

    def _transmit_loop(self) -> None:
        """Zero-drift metronome implementing 512 TU NAN epoch scheduling."""
        while self._running and not self._drones:
            time.sleep(0.01)

        # 512 TU epoch = 524,288 us = 0.524288 seconds
        TSF_EPOCH_US = 524288
        target_offsets_us = [0, 105000, 210000, 315000, 420000]
        slot = 0
        loop_counter = 0

        while self._running:
            now_us = int(time.time() * 1_000_000)
            current_epoch = now_us // TSF_EPOCH_US
            target_time_us = (current_epoch * TSF_EPOCH_US) + target_offsets_us[slot]

            if now_us >= target_time_us:
                if slot == 0:
                    current_epoch += 1
                    target_time_us = (current_epoch * TSF_EPOCH_US) + target_offsets_us[slot]
                else:
                    self.missed_deadlines += 1
                    logger.debug(f"NAN slot {slot} deadline missed")
                    slot = (slot + 1) % len(target_offsets_us)
                    continue

            sleep_time = (target_time_us - now_us) / 1_000_000.0
            if sleep_time > 0:
                time.sleep(sleep_time)

            now_ts = time.time()
            tsf_us = int(now_ts * 1_000_000) % (2**64)
            ambtt_us = (current_epoch * TSF_EPOCH_US) & 0xFFFFFFFF

            for drone in self._drones:
                if not getattr(drone, "active", True):
                    continue

                serial = drone.serial
                drone_mac = self._mac_str_to_bytes(drone.mac_address)

                seq_num = self._seq_nums.get(serial, 0)
                counter = self._msg_counters.get(serial, 0)
                if hasattr(drone, "counter_override") and drone.counter_override is not None:
                    counter = drone.counter_override

                # Slot 0 represents the active Discovery Window (DW)
                if slot == 0:
                    # Early-DW contention jitter (200 us - 600 us) before Sync Beacon TX
                    time.sleep(0.0002 + random.random() * 0.0004)

                    # 1. Inject Synchronization Beacon inside DW
                    beacon_pkt = self._build_nan_beacon(drone_mac, True, seq_num, tsf_us, ambtt_us)
                    try:
                        self._sock.send(beacon_pkt)
                    except Exception as e:
                        logger.debug(f"NAN Manual Beacon TX error: {e}")

                    seq_num = (seq_num + 1) % 4096

                    # Intra-DW CSMA/CA contention jitter (500 us - 10,000 us) before SDF injection
                    time.sleep(0.0005 + random.random() * 0.0095)

                    # 2. Inject Service Discovery Frame (SDF) inside DW
                    messages = self._packet_builder(drone)
                    
                    if self.fuzz_config and self.fuzz_config.get("raw_injection"):
                        # SPARROW-03 PoC: Bypass SDF construction and inject raw malformed IEEE 802.11 byte array directly
                        # We must include the radiotap header for the monitor mode socket to accept it
                        sdf_pkt = getattr(self, "radiotap_bytes", b"") + b"".join(messages)
                    else:
                        sdf_pkt = self._build_nan_sdf(drone, drone_mac, messages, counter, seq_num)
                        
                    try:
                        self._sock.send(sdf_pkt)
                    except Exception as e:
                        logger.debug(f"NAN Manual SDF TX error: {e}")

                    seq_num = (seq_num + 1) % 4096
                    self._seq_nums[serial] = seq_num

                else:
                    # Slots 1..4: Inter-DW Discovery Beacons (100 TU interval)
                    beacon_pkt = self._build_nan_beacon(drone_mac, False, seq_num, tsf_us, ambtt_us)
                    try:
                        self._sock.send(beacon_pkt)
                    except Exception as e:
                        logger.debug(f"NAN Manual Discovery Beacon TX error: {e}")

                    seq_num = (seq_num + 1) % 4096
                    self._seq_nums[serial] = seq_num

            # Advance slot state
            slot = (slot + 1) % len(target_offsets_us)
            if slot == 0:
                loop_counter += 1
                # Increment ODID message counter roughly every 1 second (2 epochs)
                if loop_counter >= 2:
                    loop_counter = 0
                    for drone in self._drones:
                        s = drone.serial
                        c = self._msg_counters.get(s, 0)
                        self._msg_counters[s] = (c + 1) & 0xFF

    def remove_drone(self, drone: DroneState) -> None:
        """Remove state for expired drone in manual injection backend."""
        self._seq_nums.pop(drone.serial, None)
        self._msg_counters.pop(drone.serial, None)

    def close(self) -> None:
        """Close raw socket and stop transmission loop."""
        self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=1.0)
        if hasattr(self, "_sock") and self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
        logger.info("NanManualBackend closed.")

    def send_raw(self, drone_key: str, payload: bytes) -> None:
        """Send raw byte payload (stub for interfaces requiring raw transmission)."""
        logger.warning("send_raw not directly implemented for NanManualBackend; use standard drone state metronome.")

    def reset(self) -> None:
        """Reset internal sequence and ODID counters."""
        self._seq_nums.clear()
        self._msg_counters.clear()
        logger.info("NanManualBackend reset completed.")


