#!/usr/bin/env python3
import argparse
import base64
import json
import logging
import sys
from collections import defaultdict
from typing import Dict, Any, List, Optional

from scapy.all import PcapReader, Dot11

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

WIFI_SIG = b'\xfa\x0b\xbc\x0d'
BLE_SIG = b'\xfa\xff\x0d'

def extract_messages(msgs_raw: bytes, msg_count: int) -> List[str]:
    """Extract 25-byte messages and base64 encode them."""
    encoded_msgs = []
    for i in range(msg_count):
        offset = i * 25
        if offset + 25 <= len(msgs_raw):
            msg = msgs_raw[offset:offset+25]
            encoded_msgs.append(base64.b64encode(msg).decode('ascii'))
    return encoded_msgs

def try_extract_serial(msgs_raw: bytes, msg_count: int) -> Optional[str]:
    for i in range(msg_count):
        offset = i * 25
        if offset + 25 <= len(msgs_raw):
            msg = msgs_raw[offset:offset+25]
            if (msg[0] >> 4) == 0x0: # Basic ID
                serial_bytes = msg[2:22]
                return serial_bytes.decode('ascii', errors='ignore').rstrip('\x00')
    return None

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
        if idx != -1 and idx + 7 < len(raw):
            counter = raw[idx+4]
            pack_hdr = raw[idx+5]
            if (pack_hdr >> 4) == 0xF and raw[idx+6] == 0x19:
                msg_count = raw[idx+7]
                expected_len = msg_count * 25
                if idx + 8 + expected_len <= len(raw):
                    msgs_raw = raw[idx+8 : idx+8+expected_len]
                    
                    event = {
                        "time_offset_ms": time_offset_ms,
                        "transport": "wifi",
                        "counter": counter,
                        "messages_b64": extract_messages(msgs_raw, msg_count),
                        "mac": mac_addr,
                        "channel": channel_val
                    }
                    if ssid_val is not None:
                        event["ssid_b64"] = base64.b64encode(ssid_val).decode('ascii')
                    
                    serial = try_extract_serial(msgs_raw, msg_count)
                    if serial and mac_addr:
                        mac_to_serial[mac_addr] = serial
        
        # Check BLE Service Data
        if event is None:
            idx = raw.find(BLE_SIG)
            if idx != -1 and idx + 4 < len(raw):
                counter = raw[idx+3]
                next_byte = raw[idx+4]
                
                if (next_byte >> 4) == 0xF:
                    # Potential Message Pack
                    if idx + 6 < len(raw) and raw[idx+5] == 0x19:
                        msg_count = raw[idx+6]
                        expected_len = msg_count * 25
                        if idx + 7 + expected_len <= len(raw):
                            msgs_raw = raw[idx+7 : idx+7+expected_len]
                            event = {
                                "time_offset_ms": time_offset_ms,
                                "transport": "bt5",
                                "counter": counter,
                                "messages_b64": extract_messages(msgs_raw, msg_count)
                            }
                            serial = try_extract_serial(msgs_raw, msg_count)
                            if serial and mac_addr:
                                mac_to_serial[mac_addr] = serial
                else:
                    # Legacy Single Message
                    if idx + 4 + 25 <= len(raw):
                        msgs_raw = raw[idx+4 : idx+4+25]
                        event = {
                            "time_offset_ms": time_offset_ms,
                            "transport": "bt4",
                            "counter": counter,
                            "messages_b64": extract_messages(msgs_raw, 1)
                        }
                        serial = try_extract_serial(msgs_raw, 1)
                        if serial and mac_addr:
                            mac_to_serial[mac_addr] = serial
                            
        # Look for pure Message Pack (e.g. NAN without OUI)
        if event is None:
            # We look for [counter, pack_header, 0x19, msg_count] 
            # This is risky due to false positives, but we can do a heuristic
            for i in range(len(raw) - 4):
                pack_hdr = raw[i+1]
                if (pack_hdr >> 4) == 0xF and raw[i+2] == 0x19:
                    msg_count = raw[i+3]
                    # Ensure msg_count is reasonable (e.g., 1 to 10)
                    if 1 <= msg_count <= 10:
                        expected_len = msg_count * 25
                        if i + 4 + expected_len <= len(raw):
                            # Validate first message has valid type
                            first_msg_type = raw[i+4] >> 4
                            if 0 <= first_msg_type <= 5:
                                msgs_raw = raw[i+4 : i+4+expected_len]
                                counter = raw[i]
                                event = {
                                    "time_offset_ms": time_offset_ms,
                                    "transport": "nan",
                                    "counter": counter,
                                    "messages_b64": extract_messages(msgs_raw, msg_count),
                                    "mac": mac_addr,
                                    "channel": channel_val
                                }
                                if ssid_val is not None:
                                    event["ssid_b64"] = base64.b64encode(ssid_val).decode('ascii')
                                serial = try_extract_serial(msgs_raw, msg_count)
                                if serial and mac_addr:
                                    mac_to_serial[mac_addr] = serial
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
