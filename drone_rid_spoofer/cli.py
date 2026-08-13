import argparse
import json
import logging
import sys
from typing import List

from drone_rid_spoofer.helpers import ParseLocationAction, parse_location
from drone_rid_spoofer.spoofer import DroneSpoofer
from drone_rid_spoofer.transport.base import TransportBackend

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

DEFAULT_LAT: int = 473763399
DEFAULT_LNG: int = 85312562


def parse_args() -> argparse.Namespace:
    """Parse and validate command line arguments."""
    description = """
    Spoofs drone remote ID (RID) packets compliant with ASTM F3411-19/22.
    Can operate in manual mode (keyboard controlled) or automatic mode (multiple random drones).
    Supports Wi-Fi beacon frames and BLE advertisements.

    Requirements: scapy must be installed (Wi-Fi). BLE requires Linux with Bluetooth adapter.
    """

    parser = argparse.ArgumentParser(
        prog="Drone Spoofer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=description
    )

    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface name (for Wi-Fi transport)")
    parser.add_argument("-m", "--manual", action="store_true",
                        help="Manual mode with keyboard control")
    parser.add_argument("-r", "--random", type=int, default=None,
                        help="Number of random drones to spoof")
    parser.add_argument("-s", "--serial", type=str,
                        help="Custom serial number (max 20 chars)")
    parser.add_argument("-n", "--interval", type=float, default=None,
                        help="Interval between transmission of packets")
    parser.add_argument("-l", "--location", nargs=2,
                        metavar=("LATITUDE", "LONGITUDE"),
                        action=ParseLocationAction,
                        help="Initial coordinates (decimal degrees)")
    parser.add_argument("-c", "--config", type=str,
                        help="Path to scenario config JSON")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Enable verbose logging")
    parser.add_argument("-t", "--transport", type=str, default=None,
                        choices=["wifi", "ble", "nan", "both", "all"],
                        help="Transport backend (default: wifi)")
    parser.add_argument("--ble-adapter", type=str, default=None,
                        help="BLE adapter name (default: hci0). If BLE transport is used")
    parser.add_argument("--ble-interval", type=int, default=None,
                        help="Interval for BLE 4 legacy advertisements in ms (default: 200)")
    parser.add_argument("--ble-extended-interval", type=int, default=None,
                        help="Interval override for BLE 5 extended advertisements in ms (default: same as --ble-interval)")
    parser.add_argument("--ble-legacy", action="store_true", default=None,
                        help="Use older BT4 Legacy Advertising only (for older USB adapters that do not support BLE 5 Extended)")
    parser.add_argument("--ble-dual", action="store_true", default=None,
                        help="Enable dual broadcast of both BT4 Legacy and BT5 Extended payloads simultaneously (reduces concurrency)")
    parser.add_argument("--wifi-ess", action="store_true", default=None,
                        help="Set the ESS capability bit on Wi-Fi beacons "
                             "(default: off; spoofed drone is not advertised as an AP)")
    parser.add_argument("--no-self-id", action="store_true", default=None,
                        help="Omit the Self ID message to reduce airtime and maximize concurrent drones")
    parser.add_argument("--wifi-channel", type=int, default=None,
                        help="Wi-Fi channel to broadcast on (default: 6)")
    parser.add_argument("--wifi-beacon-interval", type=float, default=None,
                        help="Wi-Fi beacon transmission interval in seconds. "
                             "ASTM F3411-22 requires <0.2s (200 TUs) on most channels. "
                             "Social channels (6, 149) have more lax requirements. (default: 0.1024)")
    parser.add_argument("--nan-port", type=int, default=None,
                        help="TCP port for the NAN Android Bridge (default: 8080)")
    parser.add_argument("--nan-mode", type=str, default=None, choices=["bridge", "manual"],
                        help="NAN transport backend mode: 'bridge' (Android TCP bridge) or 'manual' (Linux raw packet injection) (default: bridge)")
    parser.add_argument("--nan-cluster-id", type=str, default=None,
                        help="NAN cluster BSSID MAC string for manual injection mode (default: 50:6f:9a:01:00:00)")
    parser.add_argument("--nan-instance-id", type=lambda x: int(x, 0), default=None,
                        help="Transmitted Service Instance ID byte for manual injection mode (default: 0x10)")

    args = parser.parse_args()

    if args.serial and len(args.serial) > 20:
        parser.error("Serial number must be 20 characters or less")

    if args.random is not None and args.random < 1:
        parser.error("Number of random drones must be at least 1")

    return args


def load_config(path: str) -> dict:
    """Load scenario config from JSON."""
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def create_backends(transport: str, interface: str, ble_adapter: str,
                    ble_interval: int, ble_extended_interval: int = None,
                    ble_legacy: bool = False, ble_dual: bool = False,
                    wifi_ess: bool = False,
                    wifi_channel: int = 6, wifi_beacon_interval: float = 0.1024,
                    nan_port: int = 8080, nan_mode: str = "bridge",
                    nan_cluster_id: str = "50:6f:9a:01:00:00",
                    nan_instance_id: int = 0x10,
                    update_interval: float = 1.0) -> List[TransportBackend]:
    """Create transport backend instances based on configuration."""
    backends: List[TransportBackend] = []

    if transport in ("wifi", "both", "all"):
        from drone_rid_spoofer.transport.wifi import WifiBackend
        backends.append(WifiBackend(interface, ess=wifi_ess, channel=wifi_channel, beacon_interval=wifi_beacon_interval))

    if transport in ("ble", "both", "all"):
        if ble_legacy:
            from drone_rid_spoofer.transport.ble import BleLegacyBackend
            backends.append(BleLegacyBackend(
                adapter=ble_adapter,
                advertising_interval_ms=ble_interval,
            ))
        else:
            from drone_rid_spoofer.transport.ble import BleExtendedBackend
            backends.append(BleExtendedBackend(
                adapter=ble_adapter,
                legacy_interval_ms=ble_interval,
                extended_interval_ms=ble_extended_interval,
                pure_bt5=not ble_dual
            ))

    if transport in ("nan", "all"):
        if nan_mode == "manual":
            from drone_rid_spoofer.transport.nan import NanManualBackend
            backends.append(NanManualBackend(
                interface=interface,
                channel=wifi_channel,
                cluster_id=nan_cluster_id,
                instance_id=nan_instance_id,
                update_interval=update_interval
            ))
        else:
            from drone_rid_spoofer.transport.nan import NanBridgeBackend
            backends.append(NanBridgeBackend(port=nan_port, update_interval=update_interval))

    return backends


def main() -> None:
    """Main entry point."""
    try:
        args = parse_args()
        config = {}
        if args.config:
            config = load_config(args.config)
        config_global = config.get("global", {})
        args.drones_config = config.get("drones", [])

        if args.interface is None:
            args.interface = config_global.get("interface", "wlan1")
        if args.interval is None:
            args.interval = config_global.get("interval", 1.0)
        if args.random is None:
            args.random = config_global.get("random", 1)
        if args.location is None:
            cfg_location = config_global.get("location")
            if cfg_location:
                if len(cfg_location) != 2:
                    raise ValueError("global.location must have two values: [lat, lng]")
                args.location = parse_location(str(cfg_location[0]), str(cfg_location[1]))
            else:
                args.location = (DEFAULT_LAT, DEFAULT_LNG)
                logging.info("Using default location (Zurich)")

        # Transport configuration
        if args.transport is None:
            args.transport = config_global.get("transport", "wifi")

        ble_config = config_global.get("ble", {})
        if args.ble_adapter is None:
            args.ble_adapter = ble_config.get("adapter", "hci0")
        
        if args.ble_interval is None:
            args.ble_interval = ble_config.get("advertising_interval_ms", 200)
            
        if args.ble_extended_interval is None:
            args.ble_extended_interval = ble_config.get("extended_interval_ms", args.ble_interval)

        if args.ble_legacy is None:
            ble_config = config_global.get("ble", {})
            args.ble_legacy = bool(ble_config.get("legacy", False))

        if args.ble_dual is None:
            ble_config = config_global.get("ble", {})
            args.ble_dual = bool(ble_config.get("dual", False))

        if args.wifi_ess is None:
            wifi_config = config_global.get("wifi", {})
            args.wifi_ess = bool(wifi_config.get("ess", False))
            
        if getattr(args, 'wifi_channel', None) is None:
            wifi_config = config_global.get("wifi", {})
            args.wifi_channel = int(wifi_config.get("channel", 6))
            
        if getattr(args, 'wifi_beacon_interval', None) is None:
            wifi_config = config_global.get("wifi", {})
            args.wifi_beacon_interval = float(wifi_config.get("beacon_interval", 0.1024))

        nan_config = config_global.get("nan", {})
        if getattr(args, 'nan_port', None) is None:
            args.nan_port = int(nan_config.get("port", 8080))
        if getattr(args, 'nan_mode', None) is None:
            args.nan_mode = str(nan_config.get("mode", "bridge"))
        if getattr(args, 'nan_cluster_id', None) is None:
            args.nan_cluster_id = str(nan_config.get("cluster_id", "50:6f:9a:01:00:00"))
        if getattr(args, 'nan_instance_id', None) is None:
            val = nan_config.get("instance_id", 0x10)
            args.nan_instance_id = int(val, 0) if isinstance(val, str) else int(val)

        if args.random < 1:
            raise ValueError("Number of random drones must be at least 1")

        logging.info(f"Interface: {args.interface}")
        logging.info(f"Transport: {args.transport}")
        logging.info(f"Location: {args.location}")
        logging.info(f"Interval between packets(s): {args.interval}s")

        backends = create_backends(args.transport, args.interface, args.ble_adapter,
                                   args.ble_interval, 
                                   ble_extended_interval=args.ble_extended_interval,
                                   ble_legacy=args.ble_legacy,
                                   ble_dual=args.ble_dual,
                                   wifi_ess=args.wifi_ess,
                                   wifi_channel=args.wifi_channel,
                                   wifi_beacon_interval=args.wifi_beacon_interval,
                                   nan_port=args.nan_port,
                                   nan_mode=args.nan_mode,
                                   nan_cluster_id=args.nan_cluster_id,
                                   nan_instance_id=args.nan_instance_id,
                                   update_interval=args.interval)
        spoofer = DroneSpoofer(args, backends)

        try:
            if args.manual:
                spoofer.run_manual_mode()
            else:
                spoofer.run_automatic_mode()
        finally:
            for backend in backends:
                backend.close()

    except KeyboardInterrupt:
        logging.info("Shutdown complete")
    except Exception as e:
        logging.error(f"Fatal error: {e}")
        sys.exit(1)
