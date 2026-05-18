# Scenario Config

This document describes the JSON scenario file used by `spoof_drones.py`.

Note that CLI flags override config values.

## Top-level structure
```json
{
  "global": { ... },
  "drones": [ ... ]
}
```

## Global fields
- `interface` (string): Wi-Fi network interface for injection. Default: `wlan1`.
- `interval` (number): seconds between transmission batches. Default: `1.0`.
- `location` ([lat, lng]): base coordinates in decimal degrees. Default: Zurich.
- `random` (int): number of random drones if `drones` is empty. Default: `1`.
- `transport` (string): `"wifi"`, `"ble"`, or `"both"`. Default: `"wifi"`.
- `ble` (object): BLE-specific settings (optional).
  - `adapter` (string): HCI adapter name. Default: `"hci0"`.
  - `advertising_interval_ms` (int): time per BLE advertisement in ms. Default: `200`.
- `wifi` (object): Wi-Fi-specific settings (optional).
  - `channel` (int): Wi-Fi channel for injection. Default: `6`.
  - `ess` (bool): Set ESS capability (make beacon look like an AP). Default: `false`.
  - `beacon_interval` (number): Wi-Fi beacon transmission interval in seconds. Default: `0.1024`.

## Drone fields
Each entry in `drones` describes a single drone. Missing fields are generated
randomly (serial, MAC, and locations).

- `mode` (string): `"random"`, `"static"`, or `"waypoints"`. Default: `"random"`.
- `serial` (string): max 20 chars. Optional.
- `mac` (string): Wi-Fi source MAC address. Must be a **unicast, locally-administered** address
  (byte[0] bits: `0bxxxxxx10`). Randomly generated if omitted. Optional.
- `ble_mac` (string): BLE advertiser address. Must be a **Static Random** address per BT Core Spec §1.3.2
  (byte[0] bits: `0b11xxxxxx`). Randomly generated if omitted. Optional.
- `start_location` ([lat, lng]): initial drone location. Optional.
- `pilot_location` ([lat, lng]): pilot position. Optional.
- `lifespan_seconds` (int): stop transmitting after N seconds. Optional.
- `transport` (string): per-drone transport override (`"wifi"`, `"ble"`, `"both"`). Optional.
- `timestamp_offset_minutes` (number): shift the ASTM Location timestamp by this many minutes. Negative values produce timestamps in the past (e.g., `-5` = 5 minutes ago). Wraps within the hour. Default: `0`. Optional.
- `speed` (number): horizontal speed in m/s. Default: random in `[0, 25]`. Optional.
- `vertical_speed` (number): vertical speed in m/s, positive = climbing. Default: random in `[-5, 5]`. Optional.
- `geodetic_altitude` (number): altitude above WGS-84 ellipsoid in m. Default: random in `[50, 400]`. Optional.
- `pressure_altitude` (number): pressure altitude in m. Default: tracks `geodetic_altitude`. Optional.
- `height` (number): height above takeoff/ground in m. Default: random in `[10, 120]`. Optional.
- `waypoints` (list): required when `mode` is `"waypoints"`.
  - Each waypoint is `[lat, lng, hold_seconds?]`.
  - `hold_seconds` defaults to `0` when omitted.

In `random` mode the kinematic values drift each tick within plausible bounds.
In `static` and `waypoints` modes, the seeded values stay constant.

## Modes

### `random`
Drone performs a random walk around its current position each interval.

### `static`
Drone stays at its starting position.

### `waypoints`
Drone jumps to each waypoint in order and holds for `hold_seconds`. After the
last waypoint, it stays at the final location.

## Transport

### `wifi` (default)
Sends ASTM F3411-19 payloads inside Wi-Fi beacon frames with a vendor-specific
IE (OUI 0xFA0BBC). Requires a Wi-Fi adapter in monitor mode. Note that many receivers will not parse those, specially phone applications don't do good with this method.

### `ble`
Sends ASTM F3411-22 payloads as BLE `ADV_NONCONN_IND` advertisements with
Service Data UUID 0xFFFA. Requires a Linux Bluetooth adapter (HCI) and root.

One message per advertisement — the tool rotates through message types, sending
Location at 3x frequency. Multiple drones are time-multiplexed on the single
radio. With 200ms per ad, ~5 drones fit in a 1-second cycle.

### `both`
Sends on Wi-Fi and BLE simultaneously.

## Examples

Minimal one drone spoofing over Wi-Fi:
```json
{
  "global": { "interface": "wlan1" },
  "drones": [ { "mode": "random" } ]
}
```

Minimal one drone spoofing over BLE only:
```json
{
  "global": {
    "transport": "ble",
    "ble": { "adapter": "hci0" }
  },
  "drones": [ { "mode": "random" } ]
}
```

Both transports:
```json
{
  "global": {
    "interface": "wlan1",
    "transport": "both",
    "ble": { "adapter": "hci0" }
  },
  "drones": [ { "mode": "random" } ]
}
```

Waypoints (the global config is ommited):
```json
{
  "drones": [
    {
      "mode": "waypoints",
      "waypoints": [
        [47.3764, 8.5313, 2],
        [47.3766, 8.5316, 2],
        [47.3768, 8.5319, 2]
      ]
    }
  ]
}
```

Full template:
- See `scenario.template.json`.
- See `scenarios/` directory for ready-to-use examples.
