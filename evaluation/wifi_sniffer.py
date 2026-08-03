#!/usr/bin/env python3
import argparse
import time
import base64
import json
import subprocess
import sys
import os
import signal
from scapy.all import sniff, Dot11Beacon, Dot11Elt, wrpcap

# Local parser
from sniffparser import ASTM_F3411_SpecParser

# Globals
START_TIME = None
REPLAY_FILE = None
PCAP_FILE = None
MAC_TO_SERIAL = {}

def setup_monitor_mode(interface: str, channel: int):
    """Put the interface into monitor mode and set the channel."""
    print(f"[*] Setting {interface} down...")
    subprocess.run(["ip", "link", "set", interface, "down"], check=True)
    
    print(f"[*] Setting {interface} to monitor mode...")
    subprocess.run(["iw", "dev", interface, "set", "type", "monitor"], check=True)
    
    print(f"[*] Setting {interface} up...")
    subprocess.run(["ip", "link", "set", interface, "up"], check=True)
    
    print(f"[*] Setting {interface} to channel {channel}...")
    subprocess.run(["iw", "dev", interface, "set", "channel", str(channel)], check=True)

def teardown_monitor_mode(interface: str):
    """Restore the interface to managed mode."""
    print(f"\n[*] Restoring {interface} to managed mode...")
    try:
        subprocess.run(["ip", "link", "set", interface, "down"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["iw", "dev", interface, "set", "type", "managed"], check=True, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", interface, "up"], check=True, stderr=subprocess.DEVNULL)
    except Exception as e:
        print(f"[!] Failed to restore interface {interface}: {e}")

def extract_messages(msgs_raw: bytes, msg_count: int) -> list:
    """Extract 25-byte messages and base64 encode them."""
    encoded_msgs = []
    for i in range(msg_count):
        offset = i * 25
        if offset + 25 <= len(msgs_raw):
            msg = msgs_raw[offset:offset+25]
            encoded_msgs.append(base64.b64encode(msg).decode('ascii'))
    return encoded_msgs

def process_packet(pkt):
    from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11
    if not pkt.haslayer(Dot11):
        return

    # Extract MAC Address (BSSID)
    mac_addr = pkt.addr2
    if not mac_addr:
        return

    # Extract RSSI if available
    rssi = "Unknown"
    if pkt.haslayer("RadioTap"):
        try:
            # Some RadioTap headers parse dBm_AntSignal
            rssi_val = getattr(pkt["RadioTap"], "dBm_AntSignal", None)
            if rssi_val is not None:
                rssi = f"{rssi_val} dBm"
        except Exception:
            pass

    if pkt.haslayer(Dot11Beacon):
        # Look for Vendor Specific Information Elements
        current = pkt.getlayer(Dot11Beacon).payload
        found_astm = False
        
        ssid_val = None
        rates_val = None
        dsset_val = None
        tim_val = None
        erp_val = None
        esr_val = None
        astm_vendor_data = None
        
        while current:
            if isinstance(current, Dot11Elt):
                if current.ID == 0:
                    try: ssid_val = current.info.decode('ascii', errors='ignore')
                    except: pass
                elif current.ID == 1: rates_val = current.info
                elif current.ID == 3: dsset_val = current.info
                elif current.ID == 5: tim_val = current.info
                elif current.ID == 42: erp_val = current.info
                elif current.ID == 50: esr_val = current.info
                elif current.ID == 221:
                    info = current.info
                    # Check for ASTM OUI (FA:0B:BC)
                    if info.startswith(b'\xfa\x0b\xbc'):
                        vendor_data = info[3:]
                        # Check for Application Code (0x0D)
                        if len(vendor_data) > 0 and vendor_data[0] == 0x0D:
                            found_astm = True
                            astm_vendor_data = vendor_data
            current = current.payload

        if found_astm:
            _handle_astm_payload(pkt, mac_addr, rssi, astm_vendor_data, ssid_val, rates_val, dsset_val, tim_val, erp_val, esr_val, transport="wifi")
            # If it was an ASTM packet and we want to save PCAP, save it
            if PCAP_FILE is not None:
                wrpcap(PCAP_FILE, pkt, append=True)
            return

    # Check for NAN (Action frame type 0, subtype 13 or 14)
    if pkt.type == 0 and pkt.subtype in (13, 14):
        raw = bytes(pkt)
        for i in range(len(raw) - 4):
            pack_hdr = raw[i+1]
            if (pack_hdr >> 4) == 0xF and raw[i+2] == 0x19:
                msg_count = raw[i+3]
                if 1 <= msg_count <= 10:
                    expected_len = msg_count * 25
                    if i + 4 + expected_len <= len(raw):
                        first_msg_type = raw[i+4] >> 4
                        if 0 <= first_msg_type <= 5:
                            # Prepend 0x0D dummy AppCode so _handle_astm_payload parses it correctly
                            vendor_data = b'\x0D' + raw[i : i+4+expected_len]
                            _handle_astm_payload(pkt, mac_addr, rssi, vendor_data, None, None, None, None, None, None, transport="nan")
                            if PCAP_FILE is not None:
                                wrpcap(PCAP_FILE, pkt, append=True)
                            return

def _handle_astm_payload(pkt, mac_addr, rssi, vendor_data, ssid_val, rates_val, dsset_val, tim_val, erp_val, esr_val, transport="wifi"):
    try:
        # vendor_data: [AppCode][Counter][MsgType+Ver][Size][Count][Messages...]
        counter = vendor_data[1] if len(vendor_data) > 1 else 0
        pack_hdr = vendor_data[2] if len(vendor_data) > 2 else 0
        msg_type = pack_hdr >> 4
        
        # We only expect Message Packs (0xF) over Wi-Fi/NAN
        if msg_type == 0xF and len(vendor_data) > 4 and vendor_data[3] == 0x19:
            msg_count = vendor_data[4]
            expected_len = msg_count * 25
            if 5 + expected_len <= len(vendor_data):
                msgs_raw = vendor_data[5 : 5 + expected_len]
                
                t_str = "Wi-Fi NAN" if transport == "nan" else "Wi-Fi Beacon"
                print(f"🚁 {t_str} Drone Detected! MAC: {mac_addr} | RSSI: {rssi}")
                print(f"  Raw Remote ID Payload (Hex): {vendor_data.hex().upper()}")
                
                parser = ASTM_F3411_SpecParser(vendor_data[2:]) # Skip AppCode and Counter
                parsed_data = parser.parse_payload()
                
                serial = None
                if parsed_data:
                    for entry in parsed_data:
                        print(f"    - {entry}")
                        if entry.get("type") == "Basic ID" and entry.get("id"):
                            serial = entry["id"]
                            MAC_TO_SERIAL[mac_addr] = serial
                else:
                    print(f"    - (Parser returned no data. msg_count: {msg_count})")
                    
                # Write to JSONL
                if REPLAY_FILE is not None:
                    msgs_b64 = extract_messages(msgs_raw, msg_count)
                    if msgs_b64:
                        global START_TIME
                        if START_TIME is None:
                            START_TIME = float(pkt.time)
                            
                        event = {
                            "time_offset_ms": int((float(pkt.time) - START_TIME) * 1000),
                            "transport": transport,
                            "counter": counter,
                            "messages_b64": msgs_b64,
                            "mac": mac_addr
                        }
                        if serial:
                            event["serial"] = serial
                        elif mac_addr in MAC_TO_SERIAL:
                            event["serial"] = MAC_TO_SERIAL[mac_addr]
                            
                        if ssid_val: event["ssid"] = ssid_val
                        if rates_val: event["rates_b64"] = base64.b64encode(rates_val).decode('ascii')
                        if dsset_val: event["dsset_b64"] = base64.b64encode(dsset_val).decode('ascii')
                        if tim_val: event["tim_b64"] = base64.b64encode(tim_val).decode('ascii')
                        if erp_val: event["erp_b64"] = base64.b64encode(erp_val).decode('ascii')
                        if esr_val: event["esr_b64"] = base64.b64encode(esr_val).decode('ascii')
                            
                        REPLAY_FILE.write(json.dumps(event) + "\n")
                        REPLAY_FILE.flush()
                        
                print("-" * 50)
                
    except Exception as e:
        import traceback
        print(f"    - Error parsing payload: {type(e).__name__}: {e}")
        traceback.print_exc()

def main():
    parser = argparse.ArgumentParser(description="Drone Remote ID Wi-Fi Sniffer")
    parser.add_argument("--interface", default="wlan1", help="Wi-Fi Interface (default: wlan1)")
    parser.add_argument("--channel", type=int, default=6, help="Wi-Fi Channel to scan (default: 6)")
    parser.add_argument("--replay-out", help="Optional output JSONL file for use with replay_drones.py", default=None)
    parser.add_argument("--pcap-out", help="Optional output PCAP file to save raw packets", default=None)
    parser.add_argument("--no-setup", action="store_true", help="Skip bringing interface up/down (if already configured)")
    args = parser.parse_args()
    
    # Check root for interface setup and raw sockets
    if os.geteuid() != 0:
        print("[!] Warning: You usually need root privileges (sudo) to sniff Wi-Fi and configure monitor mode.")
        
    global REPLAY_FILE, PCAP_FILE
    
    if args.replay_out:
        REPLAY_FILE = open(args.replay_out, 'w')
        print(f"[*] Replay events will be saved to {args.replay_out}")
        
    if args.pcap_out:
        PCAP_FILE = args.pcap_out
        # Initialize an empty pcap file
        wrpcap(PCAP_FILE, [])
        print(f"[*] Raw PCAP data will be saved to {args.pcap_out}")

    original_sigint_handler = signal.getsignal(signal.SIGINT)

    def cleanup(signum, frame):
        print("\n[*] Stopping capture...")
        if not args.no_setup:
            teardown_monitor_mode(args.interface)
        if REPLAY_FILE:
            REPLAY_FILE.close()
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)

    try:
        if not args.no_setup:
            setup_monitor_mode(args.interface, args.channel)
            
        print(f"[*] Scanning for Wi-Fi Drone Remote ID Broadcasts on {args.interface} (Channel {args.channel})... (Press Ctrl+C to stop)")
        # Start sniffing
        sniff(iface=args.interface, prn=process_packet, store=False)
        
    except Exception as e:
        print(f"[!] Error: {e}")
        cleanup(None, None)

if __name__ == "__main__":
    main()
