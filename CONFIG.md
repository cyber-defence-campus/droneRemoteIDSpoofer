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
- `transport` (string): `"wifi"`, `"ble"`, `"nan"`, `"both"`, or `"all"`. Default: `"wifi"`.
- `ble` (object): BLE-specific settings (optional).
  - `adapter` (string): HCI adapter name. Default: `"hci0"`.
  - `advertising_interval_ms` (int): interval for BLE 4 legacy advertisements. Default: `200`.
  - `extended_interval_ms` (int): pulse rate for BLE 5 extended pack. Default: same as `advertising_interval_ms`.
  - `extended` (bool): enable BLE 5 Extended Advertising (Coded PHY). Default: `false`.
  - `legacy` (bool): force BLE 4 Legacy Advertising mode. Default: `false`.
  - `dual` (bool): enable dual BLE 4 Legacy + BLE 5 Extended Advertising. Default: `false`.
- `wifi` (object): Wi-Fi-specific settings (optional).
  - `channel` (int): Wi-Fi channel for injection. Default: `6`.
  - `ess` (bool): Set ESS capability (make beacon look like an AP). Default: `false`.
  - `beacon_interval` (number): Wi-Fi beacon transmission interval in seconds. Default: `0.1024`.
- `nan` (object): Wi-Fi NAN/Aware settings (optional).
  - `mode` (string): `"bridge"` (Android TCP bridge) or `"manual"` (direct Linux raw packet injection). Default: `"bridge"`.
  - `port` (int): TCP port to connect to the Android NAN Bridge when `mode` is `"bridge"`. Default: `8080`.
  - `cluster_id` (string): NAN Cluster BSSID MAC address for `manual` injection mode. Default: `"50:6f:9a:01:00:00"`.
  - `instance_id` (int or hex string): Transmitted Service Instance ID byte for `manual` injection mode (e.g. `16` or `"0x10"`). Default: `16` (`0x10`).

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
- `transport` (string): per-drone transport override (`"wifi"`, `"ble"`, `"nan"`, `"both"`, `"all"`). Optional.
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
Sends ASTM F3411-22 payloads as BLE advertisements with Service Data UUID 0xFFFA. 
Requires a Linux Bluetooth adapter (HCI) and root.

**Legacy Mode (BLE 4)**: Uses `ADV_NONCONN_IND` packets. Since one legacy advertisement can only hold a single ASTM message, the tool **rotates** through a sequence (2x Location + 2x Statics) to transmit the full drone state. Each drone occupies the radio for `4 * advertising_interval_ms` (e.g., 800ms by default).

**Extended Mode (BLE 5)**: Uses LE Coded PHY to transmit a full **ODID Message Pack** (containing all drone data) in a single advertisement. For maximum compatibility, the tool still maintains the Legacy rotation in the background while the Extended advertisement pulses.

In this mode, `advertising_interval_ms` sets the interval for the legacy advertisements, while `extended_interval_ms` sets the interval for the extended advertisements.

### `both`
Sends on Wi-Fi and BLE simultaneously.

### `nan`
Sends ASTM F3411-22 payloads via Wi-Fi NAN (Neighbor Awareness Networking / Wi-Fi Aware). Supports two modes:
- **`bridge` mode** (default): Connects to an Android phone running the `NaN_Bridge` app via TCP, configured by `nan.port` (default `8080`, via `adb forward tcp:8080 tcp:8080`).
- **`manual` mode**: Directly transmits IEEE 802.11 Wi-Fi Aware NAN Action Frames & Discovery Beacons via Linux raw `AF_PACKET` packet injection over a monitor mode Wi-Fi interface, requiring no Android hardware. Configurable via `nan.cluster_id` and `nan.instance_id`.

### `all`
Sends on all available transports (Wi-Fi, BLE, and NAN).

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
