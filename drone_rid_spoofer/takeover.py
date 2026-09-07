import logging
import math
import select
import socket
import struct
import sys
import time
import threading

from drone_rid_spoofer.state import DroneState
from drone_rid_spoofer.messages import MsgType
from sniffparser import ASTM_F3411_SpecParser
from scapy.all import sniff, Dot11Beacon, Dot11Elt
from scapy.error import Scapy_Exception


def make_valid_ble_mac(mac: str) -> str:
    """Ensure the top 2 bits of the MAC are set to 1 for a valid BLE Static Random Address."""
    parts = mac.split(':')
    if len(parts) != 6:
        return mac
    first_byte = int(parts[0], 16) | 0xC0
    parts[0] = f"{first_byte:02X}"
    return ':'.join(parts)


def make_valid_wifi_mac(mac: str) -> str:
    """Ensure the locally administered bit is set and multicast bit is cleared for Wi-Fi."""
    parts = mac.split(':')
    if len(parts) != 6:
        return mac
    first_byte = (int(parts[0], 16) | 0x02) & 0xFE
    parts[0] = f"{first_byte:02X}"
    return ':'.join(parts)


class TakeoverSpoofer:
    """
    Base class for sniffing Remote ID payloads and taking over a drone's session.
    Derived classes must implement run_spoofing().
    """
    def __init__(self, adapter="hci0"):
        self.adapter = adapter
        self.dev_id = int(adapter.replace("hci", "")) if adapter.startswith("hci") else 0
        self.ble_sock = None
        self.target_mac = None
        self.captured_static_messages = []
        self._static_msgs_dict = {}
        self.last_location_data = None
        self.raw_location_msg = None
        self.basic_id = b"TAKEOVER_01"
        self.last_message_count = 0
        self._legacy_msg_buffer = []
        self._sniff_lock = threading.Lock()
        self._sniffing_active = True
        
    def _build_hci_command(self, opcode: int, data: bytes) -> bytes:
        return struct.pack('<BHB', 0x01, opcode, len(data)) + data

    def start_sniffing(self, ble_interface=None, ble_scan_type="ble5", wifi_iface=None, continuous=False):
        threads = []
        
        if wifi_iface:
            wifi_thread = threading.Thread(target=self._start_wifi_sniffing, args=(wifi_iface,), daemon=True)
            threads.append(wifi_thread)
            
        if ble_interface:
            self.adapter = ble_interface
            self.dev_id = int(ble_interface.replace("hci", "")) if ble_interface.startswith("hci") else 0
            ble_thread = threading.Thread(target=self._start_ble_sniffing, args=(ble_scan_type,), daemon=True)
            threads.append(ble_thread)

        if not threads:
            raise ValueError("No interfaces provided for sniffing!")

        for t in threads:
            t.start()
            
        try:
            while self._sniffing_active and not self.target_mac:
                time.sleep(0.1)
                # Check if all threads died unexpectedly
                if not any(t.is_alive() for t in threads):
                    break
        except KeyboardInterrupt:
            logging.info("Sniffing interrupted by user.")
        finally:
            if not continuous or not self.target_mac:
                self.stop_sniffing()
            
    def stop_sniffing(self):
        """Cleanly stop all background sniffing threads."""
        self._sniffing_active = False
            
    def _start_wifi_sniffing(self, iface: str):
        logging.info(f"Listening for Wi-Fi Beacons on {iface}...")
        
        def packet_callback(pkt):
            if not self._sniffing_active: return
            
            if pkt.haslayer(Dot11Beacon):
                elt = pkt.getlayer(Dot11Elt)
                while isinstance(elt, Dot11Elt):
                    if elt.ID == 221 and elt.info.startswith(b'\xfa\x0b\xbc'):
                        astm_payload = elt.info[5:]
                        # Simulate the 0x0D app code and 0x00 counter that BLE uses so our parser works identically
                        service_data = bytes([0x0D, 0x00]) + astm_payload
                        mac_str = pkt.addr2
                        self._process_payload_threadsafe(mac_str, service_data, is_legacy=False, is_wifi=True)
                    elt = elt.payload
                    
        try:
            # Sniff until sniffing is disabled
            sniff(iface=iface, prn=packet_callback, store=0, stop_filter=lambda p: not self._sniffing_active)
        except Exception as e:
            logging.error(f"Wi-Fi Sniffing failed on {iface}: {e}")
        
    def _start_ble_sniffing(self, transport: str):
        try:
            self.ble_sock = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI)
            self.ble_sock.bind((self.dev_id,))
        except Exception as e:
            logging.error(f"Failed to open HCI socket on {self.adapter}. Did you use sudo? Error: {e}")
            return

        # Set HCI Filter to receive LE Meta Events (0x3E)
        type_mask = 1 << 4 # HCI_EVENT_PKT
        event_mask_lo = 0xFFFFFFFF
        event_mask_hi = 0xFFFFFFFF
        filter_bytes = struct.pack("<IIIH", type_mask, event_mask_lo, event_mask_hi, 0) + b'\x00\x00'
        self.ble_sock.setsockopt(socket.SOL_HCI, socket.HCI_FILTER, filter_bytes)

        try:
            # Disable Extended Scan (in case it was running)
            self.ble_sock.send(self._build_hci_command(0x2042, struct.pack("<BB", 0x00, 0x00)))
            
            if transport == "ble5":
                # Set Extended Scan Parameters
                params = struct.pack("<BBB BHH BHH", 0x01, 0x00, 0x05, 0x01, 0x0010, 0x0010, 0x01, 0x0010, 0x0010)
                self.ble_sock.send(self._build_hci_command(0x2041, params))
                # Enable Extended Scan
                self.ble_sock.send(self._build_hci_command(0x2042, struct.pack("<BBHH", 0x01, 0x00, 0x0000, 0x0000)))
            else:
                # Set Legacy Scan Parameters
                self.ble_sock.send(self._build_hci_command(0x200B, struct.pack("<BHHBB", 0x01, 0x0010, 0x0010, 0x00, 0x00)))
                # Enable Legacy Scan
                self.ble_sock.send(self._build_hci_command(0x200C, struct.pack("<BB", 0x01, 0x00)))
        except OSError as e:
            logging.error("Adapter rejected Extended Scanning commands. You need a BT 5 adapter for this script.")
            self.ble_sock.close()
            return
            
        logging.info(f"Listening for {transport} Remote ID drones on {self.adapter}...")
        
        while self._sniffing_active:
            ready, _, _ = select.select([self.ble_sock], [], [], 1.0)
            if not ready: continue
            
            try:
                pkt = self.ble_sock.recv(258)
            except OSError:
                break

            if len(pkt) < 3 or pkt[0] != 0x04: continue
                
            if pkt[1] == 0x3E: # LE Meta Event 
                if pkt[3] == 0x0D: # LE Extended Advertising Report
                    num_reports = pkt[4]
                    offset = 5
                    for _ in range(num_reports):
                        if offset + 24 > len(pkt): break
                        evt_type, addr_type, addr, p_phy, s_phy, sid, tx_pwr, rssi, p_int, d_addr_type, d_addr, d_len = struct.unpack("<HB6sBBBbbHB6sB", pkt[offset:offset+24])
                        offset += 24
                        data = pkt[offset:offset+d_len]
                        offset += d_len
                        
                        self._process_ad_data_ble(addr, data, is_legacy=False)
                elif pkt[3] == 0x02: # LE Legacy Advertising Report
                    num_reports = pkt[4]
                    offset = 5
                    for _ in range(num_reports):
                        if offset + 9 > len(pkt): break
                        evt_type, addr_type, addr, d_len = struct.unpack("<BB6sB", pkt[offset:offset+9])
                        offset += 9
                        data = pkt[offset:offset+d_len]
                        offset += d_len
                        
                        self._process_ad_data_ble(addr, data, is_legacy=True)

        # Stop scanning
        try:
            self.ble_sock.send(self._build_hci_command(0x2042, struct.pack("<BB", 0x00, 0x00)))
            self.ble_sock.send(self._build_hci_command(0x200C, struct.pack("<BB", 0x00, 0x00)))
        except: pass
        self.ble_sock.close()
        
    def _process_ad_data_ble(self, addr: bytes, data: bytes, is_legacy=False):
        # Parse AD structures looking for Service Data (0x16) with ASTM UUID (0xFAFF)
        i = 0
        while i < len(data):
            length = data[i]
            if length == 0 or i + 1 + length > len(data): break
            ad_type = data[i+1]
            ad_value = data[i+2 : i+1+length]
            
            if ad_type == 0x16 and len(ad_value) >= 2: 
                uuid16 = ad_value[:2]
                if uuid16 == b'\xfa\xff':
                    self._process_payload_threadsafe(addr, ad_value[2:], is_legacy, is_wifi=False)
                    break
            i += 1 + length
            
    def on_packet_received(self, location_data: dict, messages: list):
        """Callback invoked whenever fresh data for the locked-on target is received.
        Derived classes can override this to update spoofing trajectories dynamically.
        """
        pass
            
    def _process_payload_threadsafe(self, addr, service_data, is_legacy, is_wifi):
        with self._sniff_lock:
            self._parse_astm_payload(addr, service_data, is_legacy, is_wifi)
            
    def _parse_astm_payload(self, addr, service_data: bytes, is_legacy=False, is_wifi=False):
        if len(service_data) < 2 or service_data[0] != 0x0D:
            return
            
        counter = service_data[1]
        astm_data = service_data[2:]
        
        if len(astm_data) < 1:
            return
            
        msg_type = (astm_data[0] >> 4)
        
        messages = []
        if is_legacy:
            if len(astm_data) >= 25:
                # Accumulate legacy messages until we have at least a Location and a Basic ID
                msg = astm_data[0:25]
                mt = msg[0] >> 4
                if mt not in [m[0]>>4 for m in self._legacy_msg_buffer]:
                    self._legacy_msg_buffer.append(msg)
                
                has_loc = any((m[0]>>4) == MsgType.LOCATION for m in self._legacy_msg_buffer)
                has_bid = any((m[0]>>4) == MsgType.BASIC_ID for m in self._legacy_msg_buffer)
                
                if has_loc and has_bid:
                    messages = self._legacy_msg_buffer
                    # Synthesize a message pack for the parser
                    pack = bytes([(MsgType.PACK << 4) | 0x02, 0x19, len(messages)]) + b''.join(messages)
                    astm_data = pack
                else:
                    return # Keep accumulating
        else:
            if msg_type != 0xF:
                return # We only want full message packs (BLE 5 or Wi-Fi)

            msg_count = astm_data[2]
            for i in range(msg_count):
                offset = 3 + (i * 25)
                if offset + 25 <= len(astm_data):
                    messages.append(astm_data[offset:offset+25])
                
        parser = ASTM_F3411_SpecParser(astm_data)
        parsed_data = parser.parse_payload()
        
        location_data = None
        raw_location_msg = None
        basic_id = b"TAKEOVER_01"
        
        for entry in parsed_data:
            if entry.get("type") == "Location":
                location_data = entry
            elif entry.get("type") == "Basic ID":
                # Save the real serial number
                basic_id = entry.get("id", "TAKEOVER_01").encode('utf-8')
                
        if not location_data:
            return
            
        if is_wifi:
            if isinstance(addr, bytes):
                if len(addr) == 6:
                    mac_str = ':'.join(f'{b:02x}' for b in addr)
                else:
                    mac_str = addr.decode('utf-8', errors='ignore')
            else:
                mac_str = str(addr)
        else:
            # BLE MAC comes from HCI reversed
            mac_str = ':'.join(f'{b:02X}' for b in reversed(addr))
            
        mac_str = mac_str.upper()
            
        # If we have already locked onto a target, ignore packets from other drones.
        if self.target_mac and self.target_mac != mac_str:
            return
            
        if not self.target_mac:
            logging.info(f"Captured Target Drone: {mac_str} on {'Wi-Fi' if is_wifi else 'BLE'}")
            logging.info(f"  Current Lat: {location_data['lat']}, Lng: {location_data['lon']}, Alt: {location_data['alt']}m")
            logging.info(f"  Serial ID: {basic_id.decode('utf-8', errors='ignore')}")
        
        # Update static messages dictionary so we always have the freshest set of each type
        for msg in messages:
            mt = msg[0] >> 4
            if mt == MsgType.LOCATION:
                raw_location_msg = msg
            elif mt != MsgType.PACK: # Ignore nested message packs
                self._static_msgs_dict[mt] = msg
                
        self.captured_static_messages = list(self._static_msgs_dict.values())
                
        if raw_location_msg is None:
            return
            
        self.last_location_data = location_data
        self.raw_location_msg = raw_location_msg
        self.basic_id = basic_id
        self.target_mac = mac_str
        self.last_message_count = counter
        
        self.on_packet_received(location_data, messages)
        
    def run_spoofing(self, transport="ble5", wifi_iface="wlan1"):
        raise NotImplementedError("Derived classes must implement run_spoofing()")
