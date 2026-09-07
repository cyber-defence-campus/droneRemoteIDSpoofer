#!/usr/bin/env python3
import argparse
import json
import random
from pathlib import Path

def generate_ble_mac() -> str:
    """Generate a random Static Random Address for BLE advertising."""
    parts = [random.randint(0, 255) for _ in range(6)]
    parts[0] |= 0xC0  # force top 2 bits to 11
    return ":".join(f"{b:02x}" for b in parts)

def generate_wifi_mac() -> str:
    """Generate a random locally-administered unicast MAC for Wi-Fi."""
    parts = [random.randint(0, 255) for _ in range(6)]
    parts[0] = (parts[0] & 0xFC) | 0x02
    return ":".join(f"{b:02x}" for b in parts)

def main():
    parser = argparse.ArgumentParser(description="Generate same_mac.json scenario with diverging drones")
    parser.add_argument("--lat", type=float, default=47.3763399, help="Origin latitude (default: 47.3763399)")
    parser.add_argument("--lng", type=float, default=8.5312562, help="Origin longitude (default: 8.5312562)")
    args = parser.parse_args()

    shared_ble_mac = generate_ble_mac()
    shared_wifi_mac = generate_wifi_mac()

    # Generate waypoints for Drone 1 (going North) and Drone 2 (going South)
    # Moving at 10 m/s for 120 seconds
    speed = 10.0
    duration = 120
    lat_scale = 1 / 111320.0
    
    waypoints_1 = []
    waypoints_2 = []
    
    for t in range(duration):
        # Drone 1 goes North (increasing latitude)
        wp_lat_1 = args.lat + (speed * t * lat_scale)
        waypoints_1.append([round(wp_lat_1, 6), round(args.lng, 6), 1])
        
        # Drone 2 goes South (decreasing latitude)
        wp_lat_2 = args.lat - (speed * t * lat_scale)
        waypoints_2.append([round(wp_lat_2, 6), round(args.lng, 6), 1])

    scenario = {
        "global": {
            "interface": "wlan1",
            "interval": 1.0,
            "location": [args.lat, args.lng],
            "transport": "wifi",
            "ble": {
                "adapter": "hci0",
                "advertising_interval_ms": 200,
                "extended_interval_ms": 200,
                "extended": True
            }
        },
        "drones": [
            {
                "mode": "waypoints",
                "serial": "Same_MAC_Drone_North",
                "mac": shared_wifi_mac,
                "ble_mac": shared_ble_mac,
                "waypoints": waypoints_1,
                "pilot_location": [round(args.lat - 0.0001, 6), round(args.lng - 0.0001, 6)],
                "speed": speed,
                "geodetic_altitude": 100.0
            },
            {
                "mode": "waypoints",
                "serial": "Same_MAC_Drone_South",
                "mac": shared_wifi_mac,
                "ble_mac": shared_ble_mac,
                "waypoints": waypoints_2,
                "pilot_location": [round(args.lat - 0.0001, 6), round(args.lng - 0.0001, 6)],
                "speed": speed,
                "geodetic_altitude": 120.0
            }
        ]
    }

    out_file = Path(__file__).parent / "same_mac.json"
    with open(out_file, "w") as f:
        json.dump(scenario, f, indent=2)

    print(f"Generated {out_file.name} with origin ({args.lat}, {args.lng})")
    print(f"Shared BLE MAC:  {shared_ble_mac}")
    print(f"Shared Wi-Fi MAC: {shared_wifi_mac}")

if __name__ == "__main__":
    main()
