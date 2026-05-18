import logging
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

    def __init__(self, interface: str, ess: bool = False, protocol_version: int = 2, channel: int = 6, beacon_interval: float = 0.1024):
        self.interface = interface
        self.ess = ess
        self.protocol_version = protocol_version
        self.channel = channel
        self.beacon_interval = beacon_interval
        
        # Lock the physical interface to the target channel to ensure compliance
        try:
            subprocess.run(["sudo", "iw", "dev", self.interface, "set", "channel", str(self.channel)], check=True)
            logger.info(f"Wi-Fi interface {self.interface} locked to channel {self.channel}")
        except subprocess.CalledProcessError as e:
            logger.warning(f"Could not lock channel on {self.interface}: {e}")
        
        # Message pack header: msg_type (0xF = Pack) + ver, msg_size (0x19 = 25 bytes)
        self.pack_header_prefix = bytes([(MsgType.PACK << 4) | self.protocol_version, 0x19])
        
        # ODID message-pack counter: must increment per transmission so
        # receivers treat each beacon as a fresh message rather than a duplicate.
        self._counter = 0

        self._payloads: Dict[bytes, Tuple[dot11.Packet, dot11.Packet, str]] = {}
        self._seq_nums: Dict[bytes, int] = {}
        self._lock = threading.Lock()
        self._running = True
        self._thread = threading.Thread(target=self._transmit_loop, daemon=True)
        self._thread.start()
        logger.info(f"Wi-Fi backend started on {interface} with {self.beacon_interval*1000:.0f}ms beacon interval")

    def _transmit_loop(self) -> None:
        """Continuously broadcast all active beacons at the specified interval."""
        while self._running:
            packets = []
            current_tsf = int(time.time() * 1000000) % (2**64)
            
            with self._lock:
                items = list(self._payloads.items())
            
            for serial, (radiotap, ies, mac_addr) in items:
                with self._lock:
                    seq_num = self._seq_nums.get(serial, 0)
                    self._seq_nums[serial] = (seq_num + 1) % 4096
                
                # Dynamically instantiate the header to avoid thread contention on shared Scapy objects
                dot11_base = dot11.Dot11(
                    type=0, subtype=8,
                    addr1=self.DEST_ADDR,
                    addr2=mac_addr,
                    addr3=mac_addr,
                    SC=(seq_num << 4)
                )
                beacon_base = dot11.Dot11Beacon(cap='ESS' if self.ess else 0, timestamp=current_tsf)
                
                frame = radiotap / dot11_base / beacon_base / ies
                packets.append(frame)
                
            if packets:
                try:
                    sendp(packets, iface=self.interface, verbose=False)
                except Exception as e:
                    logger.debug(f"Wi-Fi transmit error: {e}")
                    
            time.sleep(self.beacon_interval)

    def send_messages(self, drone: DroneState, messages: List[bytes]) -> None:
        """Pack all messages into a single Wi-Fi beacon vendor-specific IE and send."""
        msg_count = bytes([len(messages) & 0xFF])
        header = bytes([self.APP_CODE, self._counter]) + self.pack_header_prefix + msg_count
        self._counter = (self._counter + 1) & 0xFF
        vendor_data = header + b''.join(messages)

        serial_str = drone.serial.decode('ascii', errors='replace')
        ssid = (self.SSID_PREFIX + serial_str)[: self.SSID_MAX_LEN]
        ie_ssid = dot11.Dot11Elt(ID='SSID', info=ssid)
        ie_rates = dot11.Dot11Elt(ID='Rates', info=self.SUPPORTED_RATES)
        ie_dsset = dot11.Dot11Elt(ID='DSset', info=bytes([self.channel]))
        ie_tim = dot11.Dot11Elt(ID='TIM', info=b'\x00\x01\x00\x00')
        ie_erp = dot11.Dot11Elt(ID='ERPinfo', info=b'\x00')
        ie_esr = dot11.Dot11Elt(ID='ESRates', info=self.EXTENDED_SUPPORTED_RATES)

        # Build the vendor-specific IE as raw bytes so the element length
        # covers both the OUI and the Remote ID payload.
        ie_vendor = dot11.Dot11Elt(ID=221, info=self.OUI + vendor_data)

        radiotap = dot11.RadioTap()
        ies = ie_ssid / ie_rates / ie_dsset / ie_tim / ie_erp / ie_esr / ie_vendor
        
        with self._lock:
            self._payloads[drone.serial] = (radiotap, ies, drone.mac_address)

    def close(self) -> None:
        self._running = False
        if self._thread.is_alive():
            self._thread.join(timeout=1.0)
        logger.info("Wi-Fi backend closed")
