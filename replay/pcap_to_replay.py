#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import sys
from collections import defaultdict
from typing import Dict, Any, List, Optional

from scapy.all import PcapReader, Dot11

import os

# Ensure repo root is in sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from drone_rid_spoofer.parser import parse_astm_payload

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

WIFI_SIG = b'\xfa\x0b\xbc\x0d'
BLE_SIG = b'\xfa\xff\x0d'

def process_pcap(pcap_path: str, output_path: str) -> None:
    try:
        reader = PcapReader(pcap_path)
    except Exception as e:
        logging.error(f"Error opening PCAP: {e}")
        sys.exit(1)
        
    events = []
    first_timestamp = None
    
    # Track serials associated with MAC addresses to group packets that lack a Basic ID
    mac_to_serial = {}
    
    count_processed = 0
    
    for pkt in reader:
        raw = bytes(pkt)
        timestamp = float(pkt.time)
        
        if first_timestamp is None:
            first_timestamp = timestamp
            
        time_offset_ms = int((timestamp - first_timestamp) * 1000)
        
        mac_addr = None
        ssid_val = None
        channel_val = 6
        if pkt.haslayer(Dot11):
            mac_addr = pkt.getlayer(Dot11).addr2
            
            # Extract SSID and Channel if present
            elt = pkt.getlayer(Dot11).payload
            while elt and hasattr(elt, 'ID'):
                if elt.ID == 0:  # SSID
                    ssid_val = elt.info
                elif elt.ID == 3:  # DS Parameter Set (channel)
                    if len(elt.info) >= 1:
                        channel_val = elt.info[0]
                elt = elt.payload
            
        event = None
        
        # Check Wi-Fi Vendor Specific
        idx = raw.find(WIFI_SIG)
        if idx != -1 and idx + 5 < len(raw):
            counter = raw[idx+4]
            astm_data = raw[idx+5:]
            parsed_msgs, msgs_b64 = parse_astm_payload(astm_data)
            if parsed_msgs and msgs_b64:
                event = {
                    "time_offset_ms": time_offset_ms,
                    "transport": "wifi",
                    "counter": counter,
                    "messages_b64": msgs_b64,
                    "mac": mac_addr,
                    "channel": channel_val
                }
                if ssid_val is not None:
                    event["ssid_b64"] = base64.b64encode(ssid_val).decode('ascii')
                
                for msg in parsed_msgs:
                    if msg.get("type") == "Basic ID" and msg.get("id") and mac_addr:
                        mac_to_serial[mac_addr] = msg["id"]
        
        # Check BLE Service Data
        if event is None:
            idx = raw.find(BLE_SIG)
            if idx != -1 and idx + 4 < len(raw):
                counter = raw[idx+3]
                astm_data = raw[idx+4:]
                parsed_msgs, msgs_b64 = parse_astm_payload(astm_data)
                if parsed_msgs and msgs_b64:
                    msg_type = (astm_data[0] >> 4) if len(astm_data) > 0 else None
                    transport = "bt5" if (msg_type == 0xF or len(msgs_b64) > 1) else "bt4"
                    event = {
                        "time_offset_ms": time_offset_ms,
                        "transport": transport,
                        "counter": counter,
                        "messages_b64": msgs_b64
                    }
                    for msg in parsed_msgs:
                        if msg.get("type") == "Basic ID" and msg.get("id") and mac_addr:
                            mac_to_serial[mac_addr] = msg["id"]
                            
        # Look for pure Message Pack (e.g. NAN without OUI)
        if event is None:
            for i in range(len(raw) - 4):
                pack_hdr = raw[i+1]
                if (pack_hdr >> 4) == 0xF and raw[i+2] == 0x19:
                    counter = raw[i]
                    astm_data = raw[i+1:]
                    parsed_msgs, msgs_b64 = parse_astm_payload(astm_data)
                    if parsed_msgs and msgs_b64:
                        event = {
                            "time_offset_ms": time_offset_ms,
                            "transport": "nan",
                            "counter": counter,
                            "messages_b64": msgs_b64,
                            "mac": mac_addr,
                            "channel": channel_val
                        }
                        if ssid_val is not None:
                            event["ssid_b64"] = base64.b64encode(ssid_val).decode('ascii')
                        for msg in parsed_msgs:
                            if msg.get("type") == "Basic ID" and msg.get("id") and mac_addr:
                                mac_to_serial[mac_addr] = msg["id"]
                        break
                                
        if event:
            # Enrich with serial if known
            if mac_addr and mac_addr in mac_to_serial:
                event["serial"] = mac_to_serial[mac_addr]
            events.append(event)
            count_processed += 1

    with open(output_path, 'w') as f:
        for event in events:
            f.write(json.dumps(event) + '\n')
            
    logging.info(f"Processed {count_processed} valid remote ID packets.")
    logging.info(f"Saved replay data to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Extract ASTM messages from PCAP into JSONL replay format.")
    parser.add_argument("pcap_file", help="Input PCAP file")
    parser.add_argument("output_jsonl", help="Output JSONL file path")
    args = parser.parse_args()
    
    process_pcap(args.pcap_file, args.output_jsonl)

if __name__ == "__main__":
    main()
