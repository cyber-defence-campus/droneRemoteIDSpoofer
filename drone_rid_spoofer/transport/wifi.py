import logging
import socket
import subprocess
import threading
import time
from typing import List, Dict, Tuple

from scapy.all import sendp
import scapy.layers.dot11 as dot11

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import MsgType
from drone_rid_spoofer.transport.base import TransportBackend

logger = logging.getLogger(__name__)


class WifiBackend(TransportBackend):
    """Wi-Fi beacon frame transport for ASTM F3411-19 RID."""

    APP_CODE = 0x0D
    DEST_ADDR = 'ff:ff:ff:ff:ff:ff'
    SSID_PREFIX = 'RID-'
    SSID_MAX_LEN = 32
    OUI = b'\xfa\x0b\xbc'
    SUPPORTED_RATES = b'\x82\x84\x8b\x96'
    EXTENDED_SUPPORTED_RATES = b'\x0c\x12\x18\x24\x30\x48\x60\x6c'

    def __init__(self, interface: str, ess: bool = False, protocol_version: int = 2, channel: int = 6, beacon_interval: float = 0.1024, rate_mbps: float = 1.0, fuzz_config: dict = None):
        super().__init__(fuzz_config)
        self.interface = interface
        self.ess = ess
        self.protocol_version = protocol_version
        self.channel = channel
        self.beacon_interval = beacon_interval
        self.rate_mbps = rate_mbps
        
        # Lock the physical interface to the target channel to ensure compliance
        try:
            subprocess.run(["sudo", "iw", "dev", self.interface, "set", "channel", str(self.channel)], check=True)
            logger.info(f"Wi-Fi interface {self.interface} locked to channel {self.channel}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Could not lock channel on {self.interface}: {e}")
            
        try:
            self._sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self._sock.bind((self.interface, 0))
            logger.info(f"Raw AF_PACKET socket created on {self.interface}")
        except Exception as e:
            logger.error(f"Failed to create raw socket on {self.interface}. Needs sudo? {e}")
            raise
        
        # Message pack header: msg_type (0xF = Pack) + ver, msg_size (0x19 = 25 bytes)
        self.pack_header_prefix = bytes([(MsgType.PACK << 4) | self.protocol_version, 0x19])
        
        # ODID message-pack counter: must increment per transmission so
        # receivers treat each beacon as a fresh message rather than a duplicate.
        self._counter = 0

        self._msg_counters: Dict[bytes, int] = {}
        self._seq_nums: Dict[bytes, int] = {}
        self._lock = threading.Lock()
        self._running = False
        self._drones = []
        self._packet_builder = None
        self._thread = None
        self.missed_deadlines = 0
        logger.info(f"Wi-Fi backend initialized on {interface} with {self.beacon_interval*1000:.0f}ms beacon interval")

    def start(self, drones: List[DroneState], packet_builder) -> None:
        self._drones = drones
        self._packet_builder = packet_builder
        self._running = True
        self._thread = threading.Thread(target=self._transmit_loop, daemon=True)
        self._thread.start()
        logger.info("Wi-Fi backend background thread started")

    def _transmit_loop(self) -> None:
        """Continuously broadcast all active beacons at the specified interval."""
        # Wait until drones are provided before starting the metronome
        while self._running and not self._drones:
            time.sleep(0.01)
            
        dest_bytes = bytes.fromhex(self.DEST_ADDR.replace(':', ''))
        
        is_5ghz = self.channel >= 36
        if is_5ghz:
            supp_rates = b'\x8c\x12\x98\x24'  # 6, 9, 12, 18 Mbps (6, 12 basic)
            ext_rates = b'\x30\x48\x60\x6c'   # 24, 36, 48, 54 Mbps
            effective_rate = 6.0 if self.rate_mbps <= 1.0 else self.rate_mbps
        else:
            supp_rates = self.SUPPORTED_RATES
            ext_rates = self.EXTENDED_SUPPORTED_RATES
            effective_rate = self.rate_mbps

        # Pre-compile static IEs that never change across drones
        ie_rates = dot11.Dot11Elt(ID='Rates', info=supp_rates)
        ie_dsset = dot11.Dot11Elt(ID='DSset', info=bytes([self.channel & 0xFF]))
        ie_tim = dot11.Dot11Elt(ID='TIM', info=b'\x00\x01\x00\x00')
        ie_erp = dot11.Dot11Elt(ID='ERPinfo', info=b'\x00')
        ie_esr = dot11.Dot11Elt(ID='ESRates', info=ext_rates)
        static_ies_bytes = bytes(ie_rates / ie_dsset / ie_tim / ie_erp / ie_esr)
        
        radiotap_bytes = bytes(dot11.RadioTap(present='Rate', Rate=effective_rate))

        next_tick = time.time()
        while self._running:
            t_loop_start = time.time()
            packets = []
            current_tsf = int(time.time() * 1000000) % (2**64)
            
            # Beacon Base (Timestamp & Cap) is identical for all drones in the same batch
            beacon_base_bytes = bytes(dot11.Dot11Beacon(cap='ESS' if self.ess else 0, timestamp=current_tsf))
            
            t_build_start = time.time()
            for drone in self._drones:
                if not getattr(drone, 'active', True):
                    continue
                    
                serial = drone.serial
                mac_addr = drone.mac_address.upper()
                
                # Check for fuzzing mutations
                if self.fuzz_config and self.fuzz_config.get("enabled"):
                    # Pass through the whole Scapy layer pipeline if mutating/fuzzing
                    beacon_payload = self._packet_builder.build_messages(drone)
                    mac_header = dot11.Dot11(addr1=self.DEST_ADDR, addr2=drone.mac_address, addr3=drone.mac_address)
                    beacon_base = dot11.Dot11Beacon(cap='ESS' if self.ess else 0, timestamp=current_tsf)
                    ie_ssid = dot11.Dot11Elt(ID='SSID', info=self.SSID_PREFIX + serial, len=len(self.SSID_PREFIX + serial))
                    vendor_ie = self._build_vendor_specific_ie(beacon_payload)
                    frame_scapy = mac_header / beacon_base / ie_ssid / ie_rates / ie_dsset / ie_tim / ie_erp / ie_esr / vendor_ie
                    mutated_frame = self._mutate_packet(frame_scapy)
                    
                    radiotap = dot11.RadioTap(present='Rate', Rate=effective_rate)
                    frame = bytes(radiotap) + bytes(mutated_frame)
                    packets.append(frame)
                    continue
                
                # Build ASTM messages from current drone state
                messages = self._packet_builder(drone)
                
                # Handle sequence and counters
                seq_num = self._seq_nums.get(serial, 0)
                self._seq_nums[serial] = (seq_num + 1) % 4096
                
                msg_count_val = self._msg_counters.get(serial, 0)
                self._msg_counters[serial] = (msg_count_val + 1) & 0xFF
                
                if self.fuzz_config and self.fuzz_config.get("raw_injection"):
                    rate_500kbps = int(self.rate_mbps * 2)
                    radiotap = dot11.RadioTap(present='Rate', Rate=rate_500kbps)
                    frame = bytes(radiotap) + b''.join(messages)
                    packets.append(frame)
                else:
                    pack_type_ver = self.fuzz_config.get("pack_type_ver", (MsgType.PACK << 4) | self.protocol_version)
                    pack_msg_size = self.fuzz_config.get("pack_msg_size", 0x19)
                    pack_msg_count = self.fuzz_config.get("pack_msg_count", len(messages) & 0xFF)
                    
                    header = bytes([self.APP_CODE, msg_count_val, pack_type_ver & 0xFF, pack_msg_size & 0xFF, pack_msg_count & 0xFF])
                    vendor_data = header + b''.join(messages)
    
                    serial_str = serial.decode('ascii', errors='replace')
                    ssid = (self.SSID_PREFIX + serial_str)[: self.SSID_MAX_LEN]
                    
                    # 1. Dynamic SSID IE: ID=0, Length, Payload
                    ssid_bytes = ssid.encode('ascii', errors='replace')
                    ie_ssid_bytes = b'\x00' + bytes([len(ssid_bytes)]) + ssid_bytes
                    
                    # 2. Dynamic Vendor IE: ID=221 (0xDD), Length, OUI + Payload
                    vendor_info = self.OUI + vendor_data
                    ie_vendor_bytes = b'\xdd' + bytes([len(vendor_info)]) + vendor_info
                    
                    # 3. Dynamic MAC Header: Frame Control (0x8000), Duration (0x0000), Addr1, Addr2, Addr3, Sequence
                    import struct
                    mac_bytes = bytes.fromhex(mac_addr.replace(':', ''))
                    seq_ctrl = (seq_num << 4) & 0xFFFF
                    mac_header_bytes = b'\x80\x00\x00\x00' + dest_bytes + mac_bytes + mac_bytes + struct.pack('<H', seq_ctrl)
                    
                    # Construct final raw frame in microseconds
                    frame = radiotap_bytes + mac_header_bytes + beacon_base_bytes + ie_ssid_bytes + static_ies_bytes + ie_vendor_bytes
                    packets.append(frame)

                
            t_build_end = time.time()
            if hasattr(self, 'build_times'):
                self.build_times.append(t_build_end - t_build_start)
                
            if packets:
                try:
                    t0 = time.time()
                    for raw_pkt in packets:
                        self._sock.send(raw_pkt)
                    t1 = time.time()
                    if hasattr(self, 'inject_times'):
                        self.inject_times.append(t1 - t0)
                except Exception as e:
                    logger.debug(f"Wi-Fi transmit error: {e}")
                    
            t_loop_end = time.time()
            if hasattr(self, 'loop_times'):
                self.loop_times.append(t_loop_end - t_loop_start)
                    
            next_tick += self.beacon_interval
            now = time.time()
            if next_tick < now:
                # We missed our deadline. Catch up to 'now' so we don't force a full sleep cycle.
                miss_amount = now - next_tick
                self.missed_deadlines += 1
                
                # Throttle the logging to prevent a cascading I/O terminal bottleneck
                #if self.missed_deadlines == 1 or self.missed_deadlines % 50 == 0:
                logger.warning(f"Wi-Fi deadline missed by {miss_amount*1000:.2f}ms! (Total missed: {self.missed_deadlines})")
                
                next_tick = now
                
            sleep_time = next_tick - time.time()
            if sleep_time > 0:
                time.sleep(sleep_time)

    def remove_drone(self, drone: DroneState) -> None:
        """Remove drone sequence numbers when expired."""
        self._seq_nums.pop(drone.serial, None)
        self._msg_counters.pop(drone.serial, None)

    def close(self) -> None:
        self._running = False
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)
        try:
            self._sock.close()
        except:
            pass
        logger.info("Wi-Fi backend closed")
