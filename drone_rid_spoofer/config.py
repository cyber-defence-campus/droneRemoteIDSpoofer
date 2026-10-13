"""Resolved spoofer configuration.

`SpooferConfig` is the single place where the three configuration sources are
merged, with precedence **CLI argument > scenario `global` block > built-in
default**, and where every default lives exactly once. Before this, that
resolution was ~75 lines of repeated ``if args.x is None: args.x =
config.get(...)`` in :func:`cli.main`, with defaults duplicated between there
and ``create_backends``.

The field names deliberately match the attributes the rest of the app reads off
the old argparse ``Namespace`` (``location``, ``interval``, ``no_self_id`` …),
so a ``SpooferConfig`` is a drop-in for anything that previously took ``args``.
"""
import argparse
import logging
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple

from drone_rid_spoofer.helpers import parse_location

logger = logging.getLogger(__name__)

# Default spoof origin: Zurich (coordinates in ASTM 1e-7 degree fixed point).
DEFAULT_LAT: int = 473763399
DEFAULT_LNG: int = 85312562


def _resolve(cli_value: Any, node: dict, key: str, default: Any,
             cast=None) -> Any:
    """Pick a value by precedence: CLI arg, then ``node[key]``, then default.

    ``cli_value`` is ``None`` when the flag was not given (argparse already
    typed it when it was). ``cast`` is applied only to a value taken from the
    config dict, where everything arrives as raw JSON.
    """
    if cli_value is not None:
        return cli_value
    if isinstance(node, dict) and key in node:
        value = node[key]
        return cast(value) if cast else value
    return default


@dataclass
class SpooferConfig:
    """Fully-resolved configuration for one spoofer run."""

    interface: str
    manual: bool
    random: int
    serial: Optional[str]
    interval: float
    location: Tuple[int, int]
    transport: str
    verbose: bool
    no_self_id: bool
    no_operator_id: bool
    drones_config: List[dict] = field(default_factory=list)
    # BLE
    ble_adapter: str = "hci0"
    ble_interval: int = 100
    ble_extended_interval: int = 100
    ble_mode: str = "extended"
    # Wi-Fi
    wifi_ess: bool = False
    wifi_channel: int = 6
    wifi_beacon_interval: float = 0.1024
    # NAN
    nan_port: int = 8080
    nan_mode: str = "bridge"
    nan_cluster_id: str = "50:6f:9a:01:00:00"
    nan_instance_id: int = 0x10

    @classmethod
    def from_sources(cls, args: argparse.Namespace,
                     raw_config: dict) -> "SpooferConfig":
        """Merge parsed CLI ``args`` with a loaded scenario ``raw_config``."""
        g = raw_config.get("global", {}) if raw_config else {}
        ble = g.get("ble", {})
        wifi = g.get("wifi", {})
        nan = g.get("nan", {})
        drones = raw_config.get("drones", []) if raw_config else []

        random_count = int(_resolve(args.random, g, "random", 1, int))
        if random_count < 1:
            raise ValueError("Number of random drones must be at least 1")

        ble_interval = int(_resolve(args.ble_interval, ble,
                                    "advertising_interval_ms", 100, int))

        return cls(
            interface=_resolve(args.interface, g, "interface", "wlan1"),
            manual=bool(args.manual),
            random=random_count,
            serial=args.serial,
            interval=float(_resolve(args.interval, g, "interval", 1.0, float)),
            location=cls._resolve_location(args.location, g),
            transport=_resolve(args.transport, g, "transport", "wifi"),
            verbose=bool(args.verbose),
            no_self_id=bool(args.no_self_id),
            no_operator_id=bool(args.no_operator_id),
            drones_config=drones,
            ble_adapter=_resolve(args.ble_adapter, ble, "adapter", "hci0"),
            ble_interval=ble_interval,
            ble_extended_interval=int(_resolve(
                args.ble_extended_interval, ble, "extended_interval_ms",
                ble_interval, int)),
            ble_mode=cls._resolve_ble_mode(args.ble_mode, ble, drones),
            wifi_ess=bool(_resolve(args.wifi_ess, wifi, "ess", False, bool)),
            wifi_channel=int(_resolve(args.wifi_channel, wifi, "channel", 6, int)),
            wifi_beacon_interval=float(_resolve(
                args.wifi_beacon_interval, wifi, "beacon_interval", 0.1024, float)),
            nan_port=int(_resolve(args.nan_port, nan, "port", 8080, int)),
            nan_mode=str(_resolve(args.nan_mode, nan, "mode", "bridge")),
            nan_cluster_id=str(_resolve(
                args.nan_cluster_id, nan, "cluster_id", "50:6f:9a:01:00:00")),
            nan_instance_id=cls._resolve_instance_id(args.nan_instance_id, nan),
        )

    @staticmethod
    def _resolve_location(cli_location, global_cfg: dict) -> Tuple[int, int]:
        if cli_location is not None:
            return cli_location
        if "location" in global_cfg:
            loc = global_cfg["location"]
            if len(loc) != 2:
                raise ValueError("global.location must have two values: [lat, lng]")
            return parse_location(str(loc[0]), str(loc[1]))
        logger.info("Using default location (Zurich)")
        return (DEFAULT_LAT, DEFAULT_LNG)

    @staticmethod
    def _resolve_ble_mode(cli_mode, ble_cfg: dict, drones: List[dict]) -> str:
        mode = cli_mode or ble_cfg.get("mode")
        if not mode:
            drone_modes = {d.get("ble_mode") for d in drones if d.get("ble_mode")}
            if len(drone_modes) > 1 or (
                "ext-legacy" in drone_modes and "extended" in drone_modes
            ):
                mode = "dual"
            else:
                mode = "extended"
        return mode.replace("_", "-")

    @staticmethod
    def _resolve_instance_id(cli_value, nan_cfg: dict) -> int:
        if cli_value is not None:
            return cli_value
        value = nan_cfg.get("instance_id", 0x10)
        return int(value, 0) if isinstance(value, str) else int(value)
