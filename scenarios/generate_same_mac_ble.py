#!/usr/bin/env python3


# Creates a scenario where two drones share the same BLE mac, but one is transmitting on legacy and the other on BLE 5

import argparse
import json
import random
from pathlib import Path


def generate_ble_mac() -> str:
    """Generate a random Static Random Address for BLE advertising (top 2 bits = 11)."""
    parts = [random.randint(0, 255) for _ in range(6)]
    parts[0] |= 0xC0  # force top 2 bits to 11 (Static Random Address)
    return ":".join(f"{b:02x}" for b in parts)

def generate_wifi_mac() -> str:
    """Generate a random locally-administered unicast MAC for Wi-Fi."""
    parts = [random.randint(0, 255) for _ in range(6)]
    parts[0] = (parts[0] & 0xFC) | 0x02
    return ":".join(f"{b:02x}" for b in parts)

def main():
    parser = argparse.ArgumentParser(
        description="Generate same_mac_ble.json scenario with 2 drones sharing the same MAC: Drone A (BLE Legacy) and Drone B (BLE 5 Extended)"
    )
    parser.add_argument("--lat", type=float, default=47.3763399, help="Origin latitude (default: 47.3763399)")
    parser.add_argument("--lng", type=float, default=8.5312562, help="Origin longitude (default: 8.5312562)")
    parser.add_argument("--duration", type=int, default=120, help="Flight duration in seconds (default: 120)")
    parser.add_argument("--out", type=str, default="same_mac_ble.json", help="Output filename in scenarios/")
    args = parser.parse_args()

    shared_ble_mac = generate_ble_mac()
    shared_wifi_mac = generate_wifi_mac()

    speed_a = 10.0
    speed_b = 20.0
    duration = args.duration
    lat_scale = 1 / 111320.0  # Approx meters to latitude degrees

    waypoints_a = []
    waypoints_b = []

    for t in range(duration):
        # Drone A flies North (increasing latitude)
        wp_lat_a = args.lat + (speed_a * t * lat_scale)
        waypoints_a.append([round(wp_lat_a, 6), round(args.lng, 6), 1])

        # Drone B flies South (decreasing latitude)
        wp_lat_b = args.lat - (speed_b * t * lat_scale)
        waypoints_b.append([round(wp_lat_b, 6), round(args.lng, 6), 1])

    scenario = {
        "global": {
            "transport": "ble",
            "interval": 1.0,
            "location": [args.lat, args.lng],
            "ble": {
                "adapter": "hci0",
                "mode": "dual",
                "advertising_interval_ms": 200,
                "extended_interval_ms": 200
            }
        },
        "drones": [
            {
                "mode": "waypoints",
                "serial": "DRONE_A",
                "description": "Drone A (Legacy)",
                "operator_id": "OP-DRONE-A",
                "transport": "ble",
                "ble_mode": "ext-legacy",
                "mac": shared_wifi_mac,
                "ble_mac": shared_ble_mac,
                "waypoints": waypoints_a,
                "pilot_location": [round(args.lat - 0.0002, 6), round(args.lng - 0.0002, 6)],
                "speed": speed_a,
                "geodetic_altitude": 100.0,
                "height": 50.0
            },
            {
                "mode": "waypoints",
                "serial": "DRONE_B",
                "description": "Drone B (BLE 5)",
                "operator_id": "OP-DRONE-B",
                "transport": "ble",
                "ble_mode": "extended",
                "mac": shared_wifi_mac,
                "ble_mac": shared_ble_mac,
                "waypoints": waypoints_b,
                "pilot_location": [round(args.lat + 0.0002, 6), round(args.lng + 0.0002, 6)],
                "speed": speed_b,
                "geodetic_altitude": 200.0,
                "height": 100.0
            }
        ]
    }

    out_file = Path(__file__).parent / args.out
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(scenario, f, indent=2)

    print(f"Generated {out_file.name} with origin ({args.lat}, {args.lng})")
    print(f"Shared BLE MAC:      {shared_ble_mac}")
    print(f"Shared Wi-Fi MAC:    {shared_wifi_mac}")
    print(f"Drone A (Legacy):    Serial='DRONE_A', ble_mode='ext-legacy', Alt=100m, Speed={speed_a}m/s (Heading North)")
    print(f"Drone B (BLE 5):     Serial='DRONE_B', ble_mode='extended',   Alt=200m, Speed={speed_b}m/s (Heading South)")

if __name__ == "__main__":
    main()
