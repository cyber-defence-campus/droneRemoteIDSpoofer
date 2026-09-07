#!/usr/bin/env python3
import threading
import time
import os
import argparse
import sys
from scapy.all import sniff
from sniffparser import packet_callback

def channel_hopper(interface, channels, hop_interval):
    """
    Background thread function that continually switches the interface
    channel.
    """
    print(f"[*] Starting channel hopper on {interface} across channels {channels}")
    while True:
        for ch in channels:
            # Try setting channel using iwconfig first
            ret = os.system(f"iwconfig {interface} channel {ch} 2>/dev/null")
            if ret != 0:
                # Fallback to iw if iwconfig fails or is missing
                os.system(f"iw dev {interface} set channel {ch} 2>/dev/null")
            
            # Wait for the specified interval before switching to the next channel
            time.sleep(hop_interval)

def main():
    parser = argparse.ArgumentParser(description="Wi-Fi Channel Hopper and Drone Remote ID Scanner")
    parser.add_argument("-i", "--interface", required=True, help="Monitor mode interface to use (e.g., wlan0, wlx...)")
    parser.add_argument("-c", "--channels", type=str, default="1,2,3,4,5,6,7,8,9,10,11,12,13", 
                        help="Comma-separated list of channels to hop through (default: 1-13)")
    parser.add_argument("-t", "--time", type=float, default=0.5, 
                        help="Time to spend on each channel in seconds (default: 0.5)")

    args = parser.parse_args()

    # Parse channels
    try:
        channels = [int(c.strip()) for c in args.channels.split(",")]
    except ValueError:
        print("[-] Error: Channels must be a comma-separated list of integers.")
        sys.exit(1)

    # Make sure we run as root (needed for iwconfig/iw and scapy sniffing)
    if os.geteuid() != 0:
        print("[-] Warning: You are not running as root. Sniffing and channel hopping usually require root privileges.")

    # Start hopper thread
    hopper_thread = threading.Thread(target=channel_hopper, args=(args.interface, channels, args.time))
    hopper_thread.daemon = True
    hopper_thread.start()

    # Start sniffing
    print(f"[*] Starting Scapy sniffer on {args.interface}...")
    try:
        sniff(iface=args.interface, prn=packet_callback, store=0)
    except KeyboardInterrupt:
        print("\n[*] Stopping scanner...")
        sys.exit(0)
    except Exception as e:
        print(f"[-] Error during sniffing: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
