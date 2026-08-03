#!/usr/bin/env python3
"""
ASTM F3411 Remote ID Over-The-Air (OTA) Fuzzing Suite.

Executes continuous or targeted fuzzing evaluation against Remote ID receiver parsers
(e.g., Sparrow-WiFi, OpenDroneID, ESP32 scanners, Android apps) across Wi-Fi Beacon,
BLE 4/5, and Wi-Fi NAN transports.

Tests parser memory resilience against:
  - Message Pack Header corruption (msg_size & msg_count mismatches)
  - Authentication Message (Type 0x02) out-of-bounds pagination & overflow
  - Missing string null terminators & ANSI format string exploits
  - Command injection & DOM XSS payload ingestion
  - Kinematic & coordinate integer overflows and projection breaking latitudes
"""
import argparse
import logging
import sys
import time

from drone_rid_spoofer.cli import create_backends, DEFAULT_LAT, DEFAULT_LNG
from drone_rid_spoofer.fuzz_generator import RidFuzzer, FuzzCategory
from drone_rid_spoofer.helpers import (
    generate_ble_mac,
    generate_wifi_mac,
    get_random_pilot_location,
    get_random_serial_number,
    random_location,
)
from drone_rid_spoofer.state import DroneState

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')


def generate_fuzz_drone() -> DroneState:
    serial = get_random_serial_number()
    lat, lng = random_location(DEFAULT_LAT, DEFAULT_LNG, 1000)
    pilot_loc = get_random_pilot_location(lat, lng)
    mac_addr = generate_wifi_mac()
    ble_addr = generate_ble_mac()

    drone = DroneState(
        serial=serial,
        pilot_location=pilot_loc,
        lat=lat,
        lng=lng,
        mac_address=mac_addr,
        ble_address=ble_addr,
        mode="hover"
    )
    drone.speed = 10.0
    drone.vertical_speed = 0.0
    drone.geodetic_altitude = 50.0
    drone.height = 50.0
    drone.direction = 180
    return drone


def main() -> None:
    parser = argparse.ArgumentParser(description="ASTM F3411 Remote ID OTA Fuzzing Suite")
    parser.add_argument("-t", "--transport", choices=["wifi", "ble", "nan", "both", "all"], default="wifi",
                        help="Transport medium(s) to broadcast fuzzing frames on simultaneously (default: wifi)")
    parser.add_argument("-f", "--fuzz-mode", choices=FuzzCategory.all_choices(), default="all",
                        help="Specific vulnerability category to fuzz, or 'all' to cycle through all attack vectors (default: all)")
    parser.add_argument("-c", "--cycle-time", type=float, default=3.0,
                        help="Duration in seconds to broadcast each fuzzed payload mutation before rotating (default: 3.0s)")
    parser.add_argument("-n", "--num-drones", type=int, default=1,
                        help="Number of concurrent simulated drones transmitting fuzzed packets (default: 1)")
    parser.add_argument("-i", "--interface", default="wlan1",
                        help="Wi-Fi monitor interface (default: wlan1)")
    parser.add_argument("--ble-adapter", default="hci0",
                        help="BLE adapter name (default: hci0)")
    parser.add_argument("--ble-legacy", action="store_true",
                        help="Use BLE 4 Legacy Advertising only")
    parser.add_argument("--ble-dual", action="store_true",
                        help="Use dual broadcast of both BLE 4 and BLE 5")
    parser.add_argument("--nan-port", type=int, default=8080,
                        help="TCP port for NAN Android bridge (default: 8080)")
    parser.add_argument("--wifi-channel", type=int, default=6,
                        help="Wi-Fi channel (default: 6)")
    args = parser.parse_args()

    logging.info(f"Initializing Remote ID Fuzzer on transport [{args.transport.upper()}] | Fuzz Mode: [{args.fuzz_mode.upper()}]")
    logging.info(f"Broadcasting with {args.num_drones} simulated transmitter(s), rotating mutation payloads every {args.cycle_time}s...")

    backends = create_backends(
        transport=args.transport,
        interface=args.interface,
        ble_adapter=args.ble_adapter,
        ble_interval=200,
        ble_legacy=args.ble_legacy,
        ble_dual=args.ble_dual,
        wifi_ess=False,
        wifi_channel=args.wifi_channel,
        wifi_beacon_interval=0.1024,
        nan_port=args.nan_port,
        update_interval=1.0
    )

    fuzzer = RidFuzzer(category=args.fuzz_mode)
    drones = [generate_fuzz_drone() for _ in range(args.num_drones)]
    
    # Store dynamic fuzzed payloads per drone serial
    current_payloads = {}

    def packet_builder(drone: DroneState) -> list:
        return current_payloads.get(drone.serial, [])

    for backend in backends:
        backend.start(drones, packet_builder)

    iteration = 0
    try:
        while True:
            iteration += 1
            logging.info(f"\n================ Fuzz Cycle #{iteration} ==================")
            for drone in drones:
                msgs, cfg, desc = fuzzer.get_next_fuzz_payload(drone)
                current_payloads[drone.serial] = msgs
                for backend in backends:
                    backend.fuzz_config = cfg
                logging.info(f"[TX: {drone.serial.decode('ascii', errors='replace')}] -> {desc}")

            time.sleep(args.cycle_time)
            
    except KeyboardInterrupt:
        logging.info(f"\nFuzzing evaluation terminated by user after {iteration} test cycles.")
    finally:
        for backend in backends:
            backend.close()
        logging.info("All transport backends cleanly shut down.")


if __name__ == "__main__":
    main()
