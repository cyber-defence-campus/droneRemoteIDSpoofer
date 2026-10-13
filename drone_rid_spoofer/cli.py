import argparse
import json
import logging
import sys
from typing import List

from drone_rid_spoofer.config import DEFAULT_LAT, DEFAULT_LNG, SpooferConfig
from drone_rid_spoofer.helpers import ParseLocationAction
from drone_rid_spoofer.spoofer import DroneSpoofer
from drone_rid_spoofer.transport.base import TransportBackend

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')

# Re-exported for standalone callers (attacks/*.py) that import them from here.
__all__ = ["DEFAULT_LAT", "DEFAULT_LNG", "SpooferConfig", "create_backends", "main"]


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
                        help="Interval for BLE 4 legacy advertisements in ms (default: 100)")
    parser.add_argument("--ble-extended-interval", type=int, default=None,
                        help="Interval override for BLE 5 extended advertisements in ms (default: same as --ble-interval)")
    parser.add_argument("--ble-mode", type=str, default=None,
                        choices=["extended", "ext-legacy", "ext_legacy", "legacy", "dual"],
                        help="BLE transmission mode: 'extended' (BLE 5 Coded PHY ODID Pack, default), "
                             "'ext-legacy' (BLE 4 Legacy PDUs via Extended HCI commands, for modern BLE 5 adapters), "
                             "'legacy' (BLE 4 Legacy Advertising via classic HCI commands), "
                             "or 'dual' (both BLE 4 Legacy + BLE 5 Extended)")
    parser.add_argument("--wifi-ess", action="store_true", default=None,
                        help="Set the ESS capability bit on Wi-Fi beacons "
                             "(default: off; spoofed drone is not advertised as an AP)")
    parser.add_argument("--no-self-id", action="store_true", default=None,
                        help="Omit the Self ID message to reduce airtime and maximize concurrent drones")
    parser.add_argument("--no-operator-id", action="store_true", default=None,
                        help="Omit the Operator ID message to reduce airtime and maximize concurrent drones")
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
                    ble_mode: str = "extended",
                    wifi_ess: bool = False,
                    wifi_channel: int = 6, wifi_beacon_interval: float = 0.1024,
                    nan_port: int = 8080, nan_mode: str = "bridge",
                    nan_cluster_id: str = "50:6f:9a:01:00:00",
                    nan_instance_id: int = 0x10,
                    update_interval: float = 1.0) -> List[TransportBackend]:
    """Create transport backend instances based on configuration.

    The main app resolves every value through :class:`SpooferConfig` and passes
    them explicitly; the defaults here serve only standalone callers (e.g.
    ``attacks/*.py``) that invoke this directly.
    """
    backends: List[TransportBackend] = []

    if transport in ("wifi", "both", "all"):
        from drone_rid_spoofer.transport.wifi import WifiBackend
        backends.append(WifiBackend(interface, ess=wifi_ess, channel=wifi_channel, beacon_interval=wifi_beacon_interval))

    if transport in ("ble", "both", "all"):
        mode = ble_mode.replace("_", "-") if ble_mode else "extended"
        if mode == "legacy":
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
                extended_interval_ms=ble_extended_interval if ble_extended_interval is not None else ble_interval,
                mode=mode
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
        raw_config = load_config(args.config) if args.config else {}
        cfg = SpooferConfig.from_sources(args, raw_config)

        logging.info(f"Interface: {cfg.interface}")
        logging.info(f"Transport: {cfg.transport}")
        logging.info(f"Location: {cfg.location}")
        logging.info(f"Interval between packets(s): {cfg.interval}s")

        backends = create_backends(cfg.transport, cfg.interface, cfg.ble_adapter,
                                   cfg.ble_interval,
                                   ble_extended_interval=cfg.ble_extended_interval,
                                   ble_mode=cfg.ble_mode,
                                   wifi_ess=cfg.wifi_ess,
                                   wifi_channel=cfg.wifi_channel,
                                   wifi_beacon_interval=cfg.wifi_beacon_interval,
                                   nan_port=cfg.nan_port,
                                   nan_mode=cfg.nan_mode,
                                   nan_cluster_id=cfg.nan_cluster_id,
                                   nan_instance_id=cfg.nan_instance_id,
                                   update_interval=cfg.interval)
        spoofer = DroneSpoofer(cfg, backends)

        try:
            if cfg.manual:
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
