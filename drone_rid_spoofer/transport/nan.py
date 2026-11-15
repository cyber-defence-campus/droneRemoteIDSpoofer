"""NAN (Wi-Fi Aware) transport backends supporting both an Android App TCP bridge and direct Linux raw packet injection."""

import base64
import hashlib
import json
import logging
import math
import socket
import threading
import time
from typing import List, Optional

from scapy.all import RadioTap

from drone_rid_spoofer.generation_lock import GenerationLock
from drone_rid_spoofer.messages import MsgType
from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.transport.base import PacketBuilder, TransportBackend
from drone_rid_spoofer.transport.wifi_interface import restore_managed_mode, setup_monitor_mode

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
        self._configured_drones = set()
        self._counters = {}
        self._stop_event = threading.Event()
        self._listener_thread = None
        self._drones = []
        self._packet_builder: Optional[PacketBuilder] = None
        self._transmit_thread = None

    def _acquire(self) -> None:
        self._connect()

    def start(self, drones: List[DroneState], packet_builder: PacketBuilder,
              gen_lock: Optional[GenerationLock] = None) -> None:
        self.open()
        self._bind(drones, packet_builder, gen_lock)
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
            if self.sock is not None:
                try:
                    self.sock.close()
                except OSError:
                    pass
            self.sock = None

    def _send_command(self, cmd: dict):
        """Send a JSON command over TCP.

        Only ever called on the transmit thread (the loop and `_cleanup_drone`,
        which runs via `_drain_removals`), so the socket has a single writer and
        needs no lock. The listener thread only reads, on its own fd reference.
        """
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
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def _transmit_loop(self) -> None:
        import time
        # Wait until drones are populated
        while not self._stop_event.is_set() and not self._drones:
            time.sleep(0.01)

        next_tick = time.time()
        while not self._stop_event.is_set():
            self._drain_removals()
            for drone, messages in self._active_packets():
                # Initialize the drone on the Android bridge if not already done
                if drone.mac_address not in self._configured_drones:
                    config_cmd = {
                        "type": "CONFIG",
                        "drone_id": drone.mac_address
                    }
                    self._send_command(config_cmd)
                    self._configured_drones.add(drone.mac_address)

                drone_key = drone.mac_address

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

        # Loop exited: this thread owns the socket, so it tears it down here
        # rather than letting close() touch it from another thread.
        self._teardown()

    def _cleanup_drone(self, drone: DroneState) -> None:
        """Stop publishing and remove state for an expired drone (transmit thread)."""
        if drone.mac_address in self._configured_drones:
            stop_cmd = {
                "type": "STOP",
                "drone_id": drone.mac_address
            }
            self._send_command(stop_cmd)
            self._configured_drones.discard(drone.mac_address)
        self._counters.pop(drone.mac_address, None)

    def _teardown(self) -> None:
        """Tell the bridge to stop all publishing and close the socket.

        Runs on the transmit thread as the loop exits, so the socket has a
        single owner. Only called from close() directly when the transmit
        thread was never started.
        """
        if self.sock:
            try:
                self.sock.sendall((json.dumps({"type": "STOP_ALL"}) + "\n").encode("utf-8"))
            except Exception:
                pass
            self._configured_drones.clear()
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
            logging.info("Disconnected from NAN bridge.")

    def close(self) -> None:
        """Stop the transmit/listener threads and release the bridge socket.

        The transmit thread tears the socket down as it exits (single owner);
        close() only signals and joins. If the transmit thread was never
        started, tear down here instead.
        """
        self._stop_event.set()
        self._opened = False
        if self._transmit_thread and self._transmit_thread.is_alive():
            self._transmit_thread.join(timeout=2.0)
        else:
            self._teardown()
        if self._listener_thread:
            self._listener_thread.join(timeout=2.0)


# Maintain backward compatibility alias for scripts relying on NanBackend
NanBackend = NanBridgeBackend


class NanManualBackend(TransportBackend):
    """NAN (Wi-Fi Aware) manual userspace packet injection backend.

    Binds a raw AF_PACKET L2 socket to a monitor mode interface and injects
    standards-compliant IEEE 802.11 NAN frames directly, implementing dual-beacon
    synchronization and dynamic Service Discovery Frames (SDF) without external hardware.
    """

    NAN_SERVICE_NAME = b"org.opendroneid.remoteid"
    DEFAULT_CLUSTER_ID = "50:6f:9a:01:00:ff"
    # Wi-Fi Aware is an OFDM protocol; 6 Mbps is the lowest valid NAN data rate.
    MIN_NAN_RATE_MBPS = 6.0

    def __init__(
        self,
        interface: str,
        protocol_version: int = 2,
        channel: int = 6,
        cluster_id: str = DEFAULT_CLUSTER_ID,
        instance_id: int = 0x01,
        rate_mbps: float = MIN_NAN_RATE_MBPS,
        update_interval: float = 1.0,
        fuzz_config: Optional[dict] = None,
    ):
        super().__init__(fuzz_config)
        self.interface = interface
        self.protocol_version = protocol_version
        self.channel = channel
        self.cluster_id_str = cluster_id
        self.instance_id = instance_id & 0xFF
        # Wi-Fi Aware runs on OFDM; the lowest valid NAN data rate is 6 Mbps, so
        # clamp anything lower (e.g. a stale 1 Mbps DSSS value) up to the floor.
        if rate_mbps < self.MIN_NAN_RATE_MBPS:
            logger.warning(
                f"NAN requires OFDM >= {self.MIN_NAN_RATE_MBPS} Mbps; raising requested "
                f"{rate_mbps} Mbps to {self.MIN_NAN_RATE_MBPS} Mbps"
            )
            rate_mbps = self.MIN_NAN_RATE_MBPS
        self.rate_mbps = rate_mbps
        self.update_interval = update_interval

        self.cluster_bssid = bytes.fromhex(self.cluster_id_str.replace(":", ""))
        if len(self.cluster_bssid) != 6:
            logger.warning(f"Invalid cluster ID format {self.cluster_id_str}, falling back to default 50:6f:9a:01:00:ff")
            self.cluster_bssid = bytes.fromhex("506f9a0100ff")

        self.service_id_hash = hashlib.sha256(self.NAN_SERVICE_NAME).digest()[:6]

        self._sock = None

        # Precompute Radiotap header
        try:
            self.radiotap_bytes = bytes(RadioTap(present="Rate", Rate=self.rate_mbps))
        except Exception:
            # Fallback 8-byte minimal RadioTap header if Scapy instantiation fails
            self.radiotap_bytes = b"\x00\x00\x08\x00\x00\x00\x00\x00"

        # A single NAN cluster has one anchor master and therefore one 802.11
        # sequence-number space and one ASTM Message Pack counter, shared by the
        # anchor's beacon and every drone's SDF (mirrors the ESP32 reference).
        self._seq_num: int = 0
        self._msg_counter: int = 0
        # Distinct NAN Service Instance ID per drone: base (self.instance_id) +
        # index assigned on first appearance, mirroring the ESP32 reference's
        # DEFAULT_BASE_NAN_INSTANCE_ID + i. Keyed by serial so an identity keeps
        # its instance ID for its whole lifetime.
        self._instance_ids: dict = {}
        self._instance_seq: int = 0
        self._running = False
        self._drones: List[DroneState] = []
        self._packet_builder: Optional[PacketBuilder] = None
        self._thread: Optional[threading.Thread] = None
        self.missed_deadlines = 0

        logger.info(
            f"NanManualBackend initialized on {self.interface} | Cluster: {self.cluster_id_str} | Instance ID: 0x{self.instance_id:02X} | Rate: {self.rate_mbps} Mbps (OFDM, floor {self.MIN_NAN_RATE_MBPS})"
        )

    def _acquire(self) -> None:
        # Put the interface into monitor mode on the target channel (the process
        # already runs as root for raw injection, so no external helper is needed).
        if not setup_monitor_mode(self.interface, self.channel):
            raise RuntimeError(f"Could not put {self.interface} into monitor mode on channel {self.channel}")

        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self._sock.bind((self.interface, 0))
            logger.info(f"Raw AF_PACKET socket created on {self.interface} for NAN manual injection")
        except Exception as e:
            logger.error(f"Failed to create raw socket on {self.interface}. Needs sudo? {e}")
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None
            raise

    def start(self, drones: List[DroneState], packet_builder: PacketBuilder,
              gen_lock: Optional[GenerationLock] = None) -> None:
        self.open()
        self._bind(drones, packet_builder, gen_lock)
        self._running = True
        self._thread = threading.Thread(target=self._transmit_loop, daemon=True)
        self._thread.start()
        logger.info("NanManualBackend transmission thread started")

    def _mac_str_to_bytes(self, mac_str: str) -> bytes:
        try:
            return bytes.fromhex(mac_str.replace(":", ""))
        except Exception:
            return b"\x02\x11\x22\x33\x44\x55"

    def _anchor_mac(self, drones: List[DroneState]) -> bytes:
        """Return the MAC of the NAN anchor master for the current drone set.

        All spoofed drones advertise the same hardcoded Master Preference and
        Random Factor, so the Wi-Fi Aware Master Rank reduces to the MAC compared
        from the most-significant octet (byte 5) down to byte 0. The numerically
        greatest MAC under that ordering is the drone that would win the anchor
        election, and it is the only member that transmits cluster/sync/discovery
        beacons; every other drone just sends its SDF inside that anchor's DW.
        """
        if not drones:
            return self.cluster_bssid
        return max(
            (self._mac_str_to_bytes(d.mac_address) for d in drones),
            key=lambda m: m[::-1],
        )

    # --- ERP-OFDM (802.11g, 2.4 GHz) airtime constants -------------------
    # NAN runs on the 2.4 GHz social channel, so injected frames use ERP-OFDM.
    # These match the beacon-capacity model in the thesis and were validated
    # against a real monitor-mode capture (nRF/USB sniffer): a 277 B SDF at
    # 6 Mbps measured 429 us back-to-back (uncontended) / 501 us median
    # (contended), vs 430 us / 497.5 us predicted here.
    OFDM_PREAMBLE_US = 20.0     # STF+LTF (16 us) + SIGNAL (4 us)
    OFDM_SYMBOL_US = 4.0        # one OFDM data symbol
    OFDM_SERVICE_TAIL_BITS = 22  # 16 SERVICE + 6 tail bits padded into symbols
    OFDM_SIGNAL_EXT_US = 6.0    # ERP (802.11g) signal extension
    DIFS_US = 28.0              # SIFS 10 + 2 x 9 us OFDM slot
    # Expected uniform CSMA/CA backoff: (CWmin/2) * slot = 7.5 * 9 us. COTS
    # FullMAC adapters apply this even for raw-injected broadcasts (measured);
    # pure SoftMAC back-to-back injection omits it (set to 0 for that ceiling).
    CSMA_BACKOFF_US = 67.5
    FCS_BYTES = 4               # hardware appends a 4-byte FCS on air

    def _frame_airtime_us(self, over_air_len: int) -> float:
        """IEEE 802.11 ERP-OFDM on-air time (us) for a built frame body of
        `over_air_len` bytes (radiotap excluded; the 4-byte hardware FCS is
        added here since it is transmitted).

        Models the PLCP preamble, the PSDU rounded up to whole 4 us OFDM
        symbols at the configured rate (bits/symbol = rate_mbps * 4 us, i.e.
        24 bits/symbol at 6 Mbps), the ERP signal extension, DIFS, and the
        expected CSMA/CA backoff. This mirrors the thesis beacon-airtime model
        and the measured per-SDF spacing; it is a capacity estimate for the DW
        overrun check, not exact medium-access accounting.
        """
        if self.rate_mbps <= 0:
            return 0.0
        psdu_bits = (over_air_len + self.FCS_BYTES) * 8 + self.OFDM_SERVICE_TAIL_BITS
        bits_per_symbol = self.rate_mbps * self.OFDM_SYMBOL_US
        n_symbols = math.ceil(psdu_bits / bits_per_symbol)
        return (self.OFDM_PREAMBLE_US + n_symbols * self.OFDM_SYMBOL_US
                + self.OFDM_SIGNAL_EXT_US + self.DIFS_US + self.CSMA_BACKOFF_US)

    def _max_sdfs_per_dw(self, dw_us: float, offset_us: float,
                         beacon_len: int = 106, sdf_len: int = 273) -> int:
        """How many SDFs fit in one Discovery Window after the entry offset and
        the single anchor beacon, at the current PHY rate. Uses nominal over-air
        frame sizes, so it is an estimate for operator feedback, not an exact cap.
        """
        budget = dw_us - offset_us - self._frame_airtime_us(beacon_len)
        sdf_air = self._frame_airtime_us(sdf_len)
        if sdf_air <= 0:
            return 0
        return max(0, int(budget // sdf_air))

    def _instance_id_for(self, drone: DroneState) -> int:
        """Return this drone's distinct NAN Service Instance ID.

        Assigned once, the first time the drone is seen, as the configured base
        instance ID plus a monotonically increasing index (wrapped to a byte) so
        concurrently-active drones never share an instance ID. Mirrors the ESP32
        reference, where swarm member i uses DEFAULT_BASE_NAN_INSTANCE_ID + i.
        """
        iid = self._instance_ids.get(drone.serial)
        if iid is None:
            iid = (self.instance_id + self._instance_seq) & 0xFF
            self._instance_seq += 1
            self._instance_ids[drone.serial] = iid
        return iid

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
        # Master Indication Attribute (Attr ID 0, length 2, Pref 254, Random 0xEA)
        master_ind = b"\x00\x02\x00\xfe\xea"

        # NAN Cluster Attribute (Attr ID 1, length 13)
        ambtt_bytes = (ambtt_us & 0xFFFFFFFF).to_bytes(4, "little", signed=False)
        nan_cluster_attr = b"\x01\x0d\x00" + drone_mac + b"\xea\xfe\x00" + ambtt_bytes

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
        seq_num: int,
        instance_id: int,
    ) -> bytes:
        """Construct raw NAN Service Discovery Frame (SDF) with dynamic SDEA Service Update Indicator."""
        # 1. 802.11 MAC Header (24 bytes) - Action Frame (Subtype 13)
        fc_duration = b"\xd0\x00\x00\x00"
        # NAN Network ID (NAN spec v3.0 Sec 2.8.1): SDFs are addressed to the
        # NAN group address 51:6F:9A:01:00:00, not generic broadcast.
        dest_addr = b"\x51\x6f\x9a\x01\x00\x00"
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
            + bytes([instance_id & 0xFF, 0x00, 0x10, len(service_info) & 0xFF])
        )
        sda_attr = sda_header + service_info

        # 4. Service Descriptor Extension Attribute (SDEA) - Attr ID 14 (0x0E), len 4
        # Service Update Indicator equals ODID counter to defeat receiver OS frame deduplication
        sdea_attr = b"\x0e\x04\x00" + bytes([instance_id & 0xFF, 0x00, 0x02, counter & 0xFF])

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
        # 16 TU Discovery Window. SDFs must clear this window or receivers,
        # whose radios are only awake during the DW, never hear them.
        DW_DURATION_US = 16384
        # Fixed delay after the DW start (TBTT) before transmitting, so frames
        # land once receivers are actually listening instead of at exactly t=0.
        DW_ENTRY_OFFSET_US = 300
        target_offsets_us = [0, 105000, 210000, 315000, 420000]
        slot = 0
        loop_counter = 0

        while self._running:
            self._drain_removals()
            now_us = int(time.time() * 1_000_000)
            current_epoch = now_us // TSF_EPOCH_US
            target_time_us = (current_epoch * TSF_EPOCH_US) + target_offsets_us[slot]

            if now_us >= target_time_us:
                if slot == 0:
                    current_epoch += 1
                    target_time_us = (current_epoch * TSF_EPOCH_US) + target_offsets_us[slot]
                else:
                    # Inter-DW discovery beacon slots run outside the DW, so a
                    # late one is still received: skip ahead without counting it
                    # as a miss (only DW overruns lose frames).
                    slot = (slot + 1) % len(target_offsets_us)
                    continue

            sleep_time = (target_time_us - now_us) / 1_000_000.0
            if sleep_time > 0:
                time.sleep(sleep_time)

            now_ts = time.time()
            tsf_us = int(now_ts * 1_000_000) % (2**64)
            ambtt_us = (current_epoch * TSF_EPOCH_US) & 0xFFFFFFFF

            # One NAN cluster has exactly one anchor master, so a single drone
            # emits every beacon. The anchor is the active drone with the highest
            # Master Rank (hardcoded equal preference/random factor => MAC
            # tie-break); all other drones only inject their SDF inside the
            # anchor's Discovery Window.
            active = self._active_packets()
            anchor_mac = self._anchor_mac([d for d, _ in active])
            counter = self._msg_counter

            radiotap_len = len(self.radiotap_bytes)

            if slot == 0:
                # Small fixed offset (not jitter) so the burst lands just inside
                # the DW rather than at exactly t=0, when receivers may still be
                # waking or hopping to the channel. No randomness is needed: a
                # single radio injects every frame sequentially, so our own
                # frames can never self-collide.
                time.sleep(DW_ENTRY_OFFSET_US / 1_000_000.0)
                burst_air_us = float(DW_ENTRY_OFFSET_US)

                # 1. Inject ONE Synchronization Beacon from the anchor master
                beacon_pkt = self._build_nan_beacon(anchor_mac, True, self._seq_num, tsf_us, ambtt_us)
                try:
                    self._sock.send(beacon_pkt)
                except Exception as e:
                    logger.debug(f"NAN Manual Beacon TX error: {e}")
                self._seq_num = (self._seq_num + 1) % 4096
                burst_air_us += self._frame_airtime_us(len(beacon_pkt) - radiotap_len)

                # 2. Burst every drone's SDF inside the anchor's Discovery Window,
                # back to back. The frames are serialized by the single TX radio,
                # so there is no self-collision to space out and no CSMA backoff
                # to emulate; a tight burst also maximises DW headroom.
                for drone, messages in active:
                    drone_mac = self._mac_str_to_bytes(drone.mac_address)
                    if self.fuzz_config and self.fuzz_config.get("raw_injection"):
                        # SPARROW-03 PoC: Bypass SDF construction and inject raw malformed IEEE 802.11 byte array directly
                        # We must include the radiotap header for the monitor mode socket to accept it
                        sdf_pkt = getattr(self, "radiotap_bytes", b"") + b"".join(messages)
                    else:
                        sdf_pkt = self._build_nan_sdf(
                            drone, drone_mac, messages, counter,
                            self._seq_num, self._instance_id_for(drone),
                        )

                    try:
                        self._sock.send(sdf_pkt)
                    except Exception as e:
                        logger.debug(f"NAN Manual SDF TX error: {e}")
                    self._seq_num = (self._seq_num + 1) % 4096
                    burst_air_us += self._frame_airtime_us(len(sdf_pkt) - radiotap_len)

                # DW capacity check. sock.send() is non-blocking (it only queues
                # to the driver), so wall-clock after the loop does NOT reflect
                # when frames actually leave the antenna. Instead compare the
                # burst's estimated on-air time against the 16 TU window: if the
                # beacon + all SDFs cannot physically fit at the current PHY rate,
                # the trailing frames transmit after the DW closes and are lost on
                # receivers that only wake for the DW. Count one miss per overrun.
                if burst_air_us > DW_DURATION_US:
                    self.missed_deadlines += 1
                    # Log every overrun, matching the Wi-Fi/BLE backends which warn
                    # on each missed deadline. A NAN capacity overrun is usually
                    # persistent (it repeats every epoch while the drone count stays
                    # high), so the stream of warnings is itself the signal.
                    logger.warning(
                        f"NAN Discovery Window AIRTIME overrun: {len(active)} SDFs need "
                        f"~{burst_air_us / 1000:.1f} ms of on-air time but the "
                        f"{DW_DURATION_US / 1000:.1f} ms window at {self.rate_mbps} Mbps "
                        f"only fits ~{self._max_sdfs_per_dw(DW_DURATION_US, DW_ENTRY_OFFSET_US)} "
                        f"SDFs; trailing frames are modeled to fall outside the DW and be lost. "
                        f"NOTE: this is a modeled ERP-OFDM on-air capacity miss (symbol-rounded "
                        f"airtime + DIFS + expected CSMA backoff), NOT a wall-clock/CPU processing "
                        f"miss (total airtime overruns: {self.missed_deadlines})"
                    )

            else:
                # Slots 1..4: ONE Inter-DW Discovery Beacon from the anchor master
                beacon_pkt = self._build_nan_beacon(anchor_mac, False, self._seq_num, tsf_us, ambtt_us)
                try:
                    self._sock.send(beacon_pkt)
                except Exception as e:
                    logger.debug(f"NAN Manual Discovery Beacon TX error: {e}")
                self._seq_num = (self._seq_num + 1) % 4096

            # Advance slot state
            slot = (slot + 1) % len(target_offsets_us)
            if slot == 0:
                loop_counter += 1
                # Increment the shared ODID message counter ~every 1 second (2 epochs)
                if loop_counter >= 2:
                    loop_counter = 0
                    self._msg_counter = (self._msg_counter + 1) & 0xFF

        # Loop exited: this thread owns the socket, so it closes it here rather
        # than letting close() touch it concurrently.
        self._close_socket()

    def _cleanup_drone(self, drone: DroneState) -> None:
        """Handle an expired drone in the manual injection backend (transmit thread).

        Sequence numbers and the ASTM counter are now cluster-wide (one anchor
        master), so the only per-drone state is the assigned NAN Service Instance
        ID. If the departing drone was the anchor master, the next loop iteration
        simply re-elects the new highest-MAC survivor via `_anchor_mac`.
        """
        self._instance_ids.pop(drone.serial, None)

    def close(self) -> None:
        """Stop the transmission loop and release the raw socket.

        The socket is closed on the transmit thread as it exits so it is never
        used from two threads at once; if the thread never started, close here.
        """
        self._running = False
        self._opened = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
        else:
            self._close_socket()
        restore_managed_mode(self.interface)
        if self.missed_deadlines:
            logger.warning(
                f"NanManualBackend closed. {self.missed_deadlines} Discovery Window "
                f"AIRTIME overrun(s) occurred - the modeled on-air time of the SDF burst "
                f"exceeded the 16.384 ms window (frame bytes / PHY rate), so trailing SDFs "
                f"are expected to land outside the DW. This is a modeled on-air capacity "
                f"limit, not a wall-clock/CPU miss; reduce drone count or raise the PHY rate."
            )
        else:
            logger.info("NanManualBackend closed.")

    def _close_socket(self) -> None:
        """Close the raw socket (transmit thread on loop exit, or close())."""
        if getattr(self, "_sock", None):
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None


