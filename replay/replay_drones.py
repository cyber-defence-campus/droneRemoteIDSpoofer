#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import struct
import sys
import os
import time
from datetime import datetime

# Add the parent directory to the Python path so it can find the drone_rid_spoofer package
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scapy.all import sendp
import scapy.layers.dot11 as dot11

from drone_rid_spoofer.transport.ble import _BleBase
from drone_rid_spoofer.transport.nan import NanBackend

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')

class SingleShotBleLegacy(_BleBase):
    _ADV_ENABLE_OPCODES = (0x200A,)
    
    def __init__(self, adapter="hci0"):
        super().__init__(adapter, 200, 2)
        
    def send_messages(self, drone, messages):
        pass
        
    def _init_advertising(self):
        pass
        
    def _disable_advertising(self):
        self._send_hci_command(0x200A, b'\x00')
        
    def send_one(self, mac: str, counter: int, msg_bytes: bytes):
        if not mac:
            print("No MAC address provided for BLE Legacy advertising")
            mac = "00:11:22:33:44:55"
        addr_bytes = bytes(int(p, 16) for p in reversed(mac.split(':')))
        print("MAC address: ", mac)
        print("MAC bytes: ", addr_bytes)
        self._send_hci_command(0x2005, addr_bytes)
        
        # Set interval to 20ms (0x0020 * 0.625ms = 20ms)
        params = b'\x20\x00\x20\x00' + bytes([0x03, 0x01, 0x00]) + b'\x00'*6 + bytes([0x07, 0x00])
        self._send_hci_command(0x2006, params)
        
        ad_data = bytes([30, 0x16]) + b'\xfa\xff' + bytes([0x0D, counter]) + msg_bytes
        hci_data = bytes([len(ad_data)]) + ad_data + b'\x00' * (31 - len(ad_data))
        self._send_hci_command(0x2008, hci_data)
        
        self._send_hci_command(0x200A, b'\x01')
        time.sleep(0.035)
        self._send_hci_command(0x200A, b'\x00')


class SingleShotBleExtended(_BleBase):
    _ADV_ENABLE_OPCODES = (0x2039,)
    
    def __init__(self, adapter="hci0"):
        super().__init__(adapter, 200, 2)
        
    def send_messages(self, drone, messages):
        pass
        
    def _init_advertising(self):
        # Disable all
        self._send_hci_command(0x2039, struct.pack("<BBBHB", 0x00, 1, 0x00, 0x0000, 0x00))
        self._send_hci_command(0x2039, struct.pack("<BBBHB", 0x00, 1, 0x01, 0x0000, 0x00))
        
        # Handle 0: BT4 Legacy PDU (properties=0x0010)
        params0 = struct.pack("<BH", 0x00, 0x0010) + b'\x20\x00\x00\x20\x00\x00' + bytes([0x07, 0x01, 0x00]) + b'\x00'*6 + bytes([0x00, 0x7F, 0x01, 0x00, 0x01, 0x00, 0x00])
        self._send_hci_command(0x2036, params0)
        
        # Handle 1: BT5 Extended PDU (properties=0x0000)
        params1 = struct.pack("<BH", 0x01, 0x0000) + b'\x20\x00\x00\x20\x00\x00' + bytes([0x07, 0x01, 0x00]) + b'\x00'*6 + bytes([0x00, 0x7F, 0x03, 0x00, 0x03, 0x01, 0x00])
        self._send_hci_command(0x2036, params1)

    def _disable_advertising(self):
        self._send_hci_command(0x2039, struct.pack("<BBBHB", 0x00, 1, 0x00, 0x0000, 0x00))
        self._send_hci_command(0x2039, struct.pack("<BBBHB", 0x00, 1, 0x01, 0x0000, 0x00))
        
    def set_mac(self, handle: int, mac: str):
        addr_bytes = bytes(int(p, 16) for p in reversed(mac.split(':')))
        self._send_hci_command(0x2035, struct.pack("<B", handle) + addr_bytes)

    def send_bt4_one(self, mac: str, counter: int, msg: bytes):
        if not mac: mac = "00:11:22:33:44:55"
        self.set_mac(0, mac)
        
        ad_data = bytes([30, 0x16]) + b'\xfa\xff' + bytes([0x0D, counter]) + msg
        header = struct.pack("<BBBB", 0x00, 0x03, 0x01, len(ad_data))
        self._send_hci_command(0x2037, header + ad_data)
        
        self._send_hci_command(0x2039, struct.pack("<BBBHB", 0x01, 1, 0x00, 0x0000, 0x01))
        self._wait_for_adv_terminated(0x00, timeout=0.1)

    def send_bt5_pack(self, mac: str, counter: int, messages: list):
        if not mac: mac = "00:11:22:33:44:55"
        self.set_mac(1, mac)
        
        msg_count = len(messages) & 0xFF
        pack_header = bytes([0xF2, 0x19, msg_count])
        service_data = b'\xfa\xff' + bytes([0x0D, counter]) + pack_header + b''.join(messages)
        ad_length = 1 + len(service_data)
        ad_payload = bytes([ad_length, 0x16]) + service_data
        
        header = struct.pack("<BBBB", 0x01, 0x03, 0x01, len(ad_payload))
        self._send_hci_command(0x2037, header + ad_payload)
        
        self._send_hci_command(0x2039, struct.pack("<BBBHB", 0x01, 1, 0x01, 0x0000, 0x01))
        self._wait_for_adv_terminated(0x01, timeout=0.1)


def send_wifi(interface: str, mac: str, counter: int, messages: list, 
              ssid: str = None, 
              rates_b64: str = None, 
              dsset_b64: str = None, 
              tim_b64: str = None, 
              erp_b64: str = None, 
              esr_b64: str = None):
    msg_count = len(messages)
    payload = b''.join(messages)
    
    vendor_data = bytes([0x0D, counter, 0xF2, 0x19, msg_count]) + payload
    
    dest = "ff:ff:ff:ff:ff:ff"
    src = mac if mac else "00:11:22:33:44:55"
    dot11_base = dot11.Dot11(type=0, subtype=8, addr1=dest, addr2=src, addr3=src)
    beacon = dot11.Dot11Beacon(cap=0)
    
    if not ssid: ssid = "RID-Replay"
    rates = base64.b64decode(rates_b64) if rates_b64 else b'\x82\x84\x8b\x96'
    dsset = base64.b64decode(dsset_b64) if dsset_b64 else bytes([6])
    tim = base64.b64decode(tim_b64) if tim_b64 else b'\x00\x01\x00\x00'
    erp = base64.b64decode(erp_b64) if erp_b64 else b'\x00'
    esr = base64.b64decode(esr_b64) if esr_b64 else b'\x0c\x12\x18\x24\x30\x48\x60\x6c'
        
    ie_ssid = dot11.Dot11Elt(ID='SSID', info=ssid)
    ie_rates = dot11.Dot11Elt(ID='Rates', info=rates)
    ie_dsset = dot11.Dot11Elt(ID='DSset', info=dsset)
    ie_tim = dot11.Dot11Elt(ID='TIM', info=tim)
    ie_erp = dot11.Dot11Elt(ID='ERPinfo', info=erp)
    ie_esr = dot11.Dot11Elt(ID='ESRates', info=esr)
    
    ie_vendor = dot11.Dot11Elt(ID=221, info=b'\xfa\x0b\xbc' + vendor_data)
    radiotap = dot11.RadioTap()
    
    ies = ie_ssid / ie_rates / ie_dsset / ie_tim / ie_erp / ie_esr / ie_vendor
    frame = radiotap / dot11_base / beacon / ies
    sendp(frame, iface=interface, verbose=False)


def main():
    parser = argparse.ArgumentParser(description="Replay extracted ASTM payloads.")
    parser.add_argument("jsonl_file", help="Input JSONL replay file")
    parser.add_argument("--transport", help="Override transport (wifi, bt4, bt5, nan, original)", default="original")
    parser.add_argument("--wifi-iface", default="wlan1", help="Wi-Fi Interface (default: wlan1)")
    parser.add_argument("--ble-adapter", default="hci0", help="BLE adapter (default: hci0)")
    args = parser.parse_args()

    events = []
    with open(args.jsonl_file, 'r') as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
                
    if not events:
        logging.error("No events found in file.")
        sys.exit(1)
        
    logging.info(f"Loaded {len(events)} events.")
    
    # Check if we will be transmitting any BT5 packets.
    # If so, we MUST use SingleShotBleExtended for both BT4 and BT5 to avoid 
    # mixing Legacy (0x2006) and Extended (0x2036) commands, which causes 0x0C errors.
    # If strictly BT4, we use SingleShotBleLegacy to support older BT4 adapters.
    requires_extended_commands = False
    for e in events:
        t = args.transport if args.transport != "original" else e["transport"]
        if t == "bt5":
            requires_extended_commands = True
            break
            
    ble_legacy = None
    ble_extended = None
    nan_backend = None
    
    try:
        start_time = time.time()
        for idx, event in enumerate(events):
            orig_t = event["transport"]
            t = args.transport if args.transport != "original" else orig_t
            
            if orig_t == "bt4" and args.transport == "original":
                t = "bt4"
                
            early_offset = 0.0175 if t in ("bt4", "bt5") else 0.0
            target_time = start_time + (event["time_offset_ms"] / 1000.0) - early_offset
            
            now = time.time()
            if target_time > now:
                time.sleep(target_time - now)
                
            messages = [base64.b64decode(m) for m in event.get("messages_b64", [])]
            
            # Patch timestamps in Location messages (Message Type 2) to be live
            live_now = datetime.now()
            tenth_seconds = (live_now.minute * 600 + live_now.second * 10 + live_now.microsecond // 100000) % 6000
            patched_messages = []
            for msg in messages:
                if (msg[0] >> 4) == 2 and len(msg) >= 23:
                    msg_ba = bytearray(msg)
                    struct.pack_into("<H", msg_ba, 21, tenth_seconds)
                    patched_messages.append(bytes(msg_ba))
                else:
                    patched_messages.append(msg)
            messages = patched_messages
            
            mac = event.get("mac")
            counter = event.get("counter", 0)
            
            if "raw_payload_b64" in event:
                raw_bytes = base64.b64decode(event["raw_payload_b64"])
                if t == "nan":
                    if not nan_backend:
                        nan_backend = NanBackend()
                    session_id = event.get("session_id", mac) if mac else "00:11:22:33:44:55"
                    nan_backend.send_raw(session_id, raw_bytes)
                continue
            
            if t == "wifi":
                ssid = event.get("ssid")
                rates_b64 = event.get("rates_b64")
                dsset_b64 = event.get("dsset_b64")
                tim_b64 = event.get("tim_b64")
                erp_b64 = event.get("erp_b64")
                esr_b64 = event.get("esr_b64")
                send_wifi(args.wifi_iface, mac, counter, messages, 
                          ssid=ssid, rates_b64=rates_b64, dsset_b64=dsset_b64, 
                          tim_b64=tim_b64, erp_b64=erp_b64, esr_b64=esr_b64)
            elif t == "bt4":
                if requires_extended_commands:
                    if not ble_extended:
                        ble_extended = SingleShotBleExtended(args.ble_adapter)
                    for msg in messages:
                        ble_extended.send_bt4_one(mac, counter, msg)
                else:
                    if not ble_legacy:
                        ble_legacy = SingleShotBleLegacy(args.ble_adapter)
                    for msg in messages:
                        ble_legacy.send_one(mac, counter, msg)
            elif t == "bt5":
                if not ble_extended:
                    ble_extended = SingleShotBleExtended(args.ble_adapter)
                ble_extended.send_bt5_pack(mac, counter, messages)
            elif t == "nan":
                if not nan_backend:
                    nan_backend = NanBackend()
                # Dummy DroneState
                class DummyState:
                    mac_address = event.get("session_id", mac) if mac else "00:11:22:33:44:55"
                    counter_override = counter
                nan_backend.send_messages(DummyState(), messages)
                
            if idx % 10 == 0:
                logging.info(f"Replayed {idx}/{len(events)} events...")
                
    except KeyboardInterrupt:
        logging.info("Replay interrupted by user.")
    finally:
        if ble_legacy:
            ble_legacy.close()
        if ble_extended:
            ble_extended.close()
        if nan_backend:
            nan_backend.close()
            
    logging.info("Replay complete.")

if __name__ == "__main__":
    main()
