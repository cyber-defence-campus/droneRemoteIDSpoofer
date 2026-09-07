# Architecture

## Overview
The **Drone Remote ID Spoofer** is a modular, high-performance toolkit for generating, broadcasting, fuzzing, and evaluating ASTM F3411-19/22 Remote ID (RID) / OpenDroneID transmissions.

It supports all standard RF broadcast transports:
- **Wi-Fi Beacon** (IEEE 802.11 Vendor-Specific Information Elements on 2.4 GHz & 5.8 GHz)
- **Bluetooth Low Energy** (BLE 4 Legacy Advertising, BLE 5 Extended Advertising with LE Coded PHY Message Packs, Extended Legacy via Extended HCI, and Dual broadcast)
- **Wi-Fi NAN / Wi-Fi Aware** (Neighbor Awareness Networking via Android TCP Bridge or Direct Linux Raw Packet Injection)

The codebase is structured as a Python package (`drone_rid_spoofer/`) with entry-point shims (`spoof_drones.py`, `ephemeral_swarm.py`, `fuzz_rid.py`, etc.).

---

## Package Structure

```
spoof_drones.py                         # Main entry-point CLI shim
ephemeral_swarm.py                      # Multi-transport identity-rotation swarm saturation tool
fuzz_rid.py                             # Over-the-air protocol & parser fuzzing harness
takeover_figure8.py                     # Real-time drone sniffing and figure-8 trajectory takeover
takeover_predictive.py                  # Real-time sniffing and Kalman-like predictive trajectory hiding
sniffparser.py                          # ASTM F3411 packet dissector and sniffer parser
interface-monitor.sh                    # Helper script for putting Wi-Fi interfaces into monitor mode

drone_rid_spoofer/
├── __init__.py
├── __main__.py                         # python -m drone_rid_spoofer
├── cli.py                              # CLI argument parsing, scenario loading, backend factory
├── state.py                            # DroneState dataclass (kinematics, timers, coordinates)
├── messages.py                         # ASTM F3411-19/22 message builders (Types 0, 1, 2, 3, 4, 5, 0xF)
├── helpers.py                          # MAC/BLE generator, location math, coordinate parsing
├── spoofer.py                          # DroneSpoofer controller (manual WASD + automatic swarms)
├── takeover.py                         # Sniffing, session hijacking, and trajectory prediction engine
├── fuzz_generator.py                   # Protocol mutation engine for OTA fuzzing
└── transport/
    ├── __init__.py
    ├── base.py                         # TransportBackend abstract base class
    ├── wifi.py                         # WifiBackend (raw AF_PACKET 802.11 beacon injection)
    ├── ble.py                          # BleLegacyBackend & BleExtendedBackend (raw Linux HCI sockets)
    └── nan.py                          # NanBridgeBackend (Android TCP) & NanManualBackend (raw 802.11 NAN)

scenarios/                              # Pre-configured scenario JSON files
NaN_Bridge/                             # Android app source for Android Wi-Fi Aware broadcasting
evaluation/                             # Benchmarking suite (wifi_capacity.py, ble_capacity.py, cts_inject)
replay/                                 # PCAP capture replay engine (replay_drones.py, pcap_to_replay.py)
```

---

## Key Abstractions

### 1. ASTM Remote ID Messages (`messages.py`)
Pure builder functions produce 25-byte ASTM F3411-19/22 payloads across all transports:
- `build_basic_id(serial)` — **Message Type 0x0**: Drone identity and serial number.
- `build_location_vector(lat, lng, dir, speed, ...)` — **Message Type 0x1**: Geodetic location, altitude, velocity vector, heading, and timestamp.
- `build_auth(page_header, auth_data)` — **Message Type 0x2**: Authentication data pages.
- `build_self_id(description)` — **Message Type 0x3**: Plaintext drone self-description.
- `build_system(pilot_lat, pilot_lng)` — **Message Type 0x4**: Pilot/operator location and system status.
- `build_operator_id()` — **Message Type 0x5**: Operator registration ID.
- `build_all_messages(drone)` — Convenience helper generating the full set of ASTM payloads for a given drone state.

---

### 2. Transport Architecture & Threading Model (`transport/`)

The transport layer uses an **asynchronous background-threaded lifecycle**. Instead of synchronous single-packet transmissions, the spoofer starts background threads on each active backend:

```python
backend.start(drones, packet_builder)
```

Each transport backend runs its own high-frequency loop optimized for its specific RF timing requirements, decoupled from the spoofer's 1 Hz kinematic update tick:

#### **Wi-Fi Beacon (`WifiBackend` in `transport/wifi.py`)**
- Assembles raw IEEE 802.11 Beacon frames and injects them via Linux raw `AF_PACKET` sockets on a monitor-mode interface.
- Pre-compiles static Information Elements (Rates, DS Set, TIM, ERP, Extended Rates) for microsecond-level batch generation.
- Appends SSID (e.g. `RID-Serial`) and the ASTM Vendor-Specific IE (OUI `0xFA0BBC` / Type `0x0D`).
- Supports 2.4 GHz (channels 1–14) and 5.8 GHz (channels 36–165), Radiotap rate injection, and ESS capability bit toggling.

#### **BLE Transport (`transport/ble.py`)**
Operates directly over Linux raw HCI sockets (`AF_BLUETOOTH`, `BTPROTO_HCI`):
- **`BleLegacyBackend`**: Uses classic Bluetooth 4.0 HCI opcodes (`0x2005`–`0x200A`) to broadcast `ADV_NONCONN_IND` packets on LE 1M PHY. Emits one 25-byte message per advertisement, rotating Location (1 Hz) and staggered static messages (0.33 Hz).
- **`BleExtendedBackend`**: Uses Bluetooth 5.0+ Extended Advertising HCI opcodes (`0x2035`–`0x2039`) with configurable modes:
  - **`extended`** *(default)*: Broadcasts full OpenDroneID Message Packs on Handle 1 using **LE Coded PHY** (Long Range).
  - **`ext-legacy`**: Broadcasts standard BLE 4 `ADV_NONCONN_IND` legacy advertisements on Handle 0 (LE 1M PHY) using Extended HCI commands. Used for modern BLE 5 adapters when classic HCI opcodes return `0x0C (Command Disallowed)`.
  - **`dual`**: Concurrently transmits both Handle 0 (Legacy PDU) and Handle 1 (Extended PDU).

#### **Wi-Fi NAN / Aware (`transport/nan.py`)**
- **`NanBridgeBackend`**: Forwards ODID Message Packs over TCP (default port `8080`) to an Android device running the `NaN_Bridge` app via `adb forward`.
- **`NanManualBackend`**: Directly injects raw IEEE 802.11 NAN Action Frames and Discovery Beacons on channel 6 (2437 MHz) via `AF_PACKET`. Encapsulates messages in NAN Service Descriptor Attributes (SDA) with NAN Cluster BSSID `50:6f:9a:01:00:00` and Service Info OUI `FA:0B:BC`.

---

### 3. Drone State & Kinematics Engine (`state.py`, `spoofer.py`)

- **`DroneState`**: Encapsulates a drone's dynamic position (lat/lng, altitude, pressure altitude, height), velocity vector, heading, pilot position, Wi-Fi MAC, BLE Static Random address, lifespan timer, and waypoint queue.
- **`DroneSpoofer` Modes**:
  - **`random`**: Random walk kinematic drift simulating plausible drone movement.
  - **`static`**: Fixed geographic location.
  - **`waypoints`**: Flight along predetermined GPS coordinates with per-waypoint hold timers.
  - **`manual`**: Real-time WASD interactive keyboard steering.

---

### 4. Security Evaluation, Fuzzing & Takeover (`takeover.py`, `fuzz_generator.py`)

- **Takeover Engine (`takeover.py`)**: Sniffs real Remote ID broadcasts over the air, clones target drone telemetry, computes predictive Kalman-like flight paths, and injects figure-8 or intercept trajectories to spoof/hijack sessions on receiver displays.
- **Fuzzing Engine (`fuzz_generator.py`)**: Mutates ASTM message headers, authentication pagination parameters (out-of-bounds page counts, conflicting pages), message pack lengths, and string fields (XSS, SQLi, format strings) to test receiver parser resilience.

---

## Data Flow

```
+-------------------------------------------------------------------------+
|                              CLI / Config                               |
|              (cli.py: parse_args() / load_config())                     |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                           Backend Factory                               |
|               (create_backends() -> List[TransportBackend])             |
+-------------------------------------------------------------------------+
                                    |
                                    v
+-------------------------------------------------------------------------+
|                        Drone Spoofer Controller                         |
|                           (DroneSpoofer)                                |
|                                                                         |
|  1. Seeds DroneState list (manual, random swarm, or waypoint routes)    |
|  2. Calls backend.start(drones, packet_builder)                         |
+-------------------------------------------------------------------------+
        |                                                 |
        | (Main Thread: 1 Hz Loop)                       | (Background Threads: Asynchronous)
        v                                                 v
+-----------------------------+           +-------------------------------+
|     Kinematic Updates       |           |     Transport Broadcast Loops |
|                             |           |                               |
| - WASD keyboard steering    |           | - WifiBackend (102.4ms TUs)   |
| - Random walk drift         | --------> | - BleExtendedBackend (Dwell)  |
| - Waypoint step & hold      |  Updates  | - NanManualBackend (512ms DW) |
| - Lifespan expiration check |  State    |                               |
+-----------------------------+           | Pulls serialized ASTM packets |
                                          | via packet_builder(drone)     |
                                          | and transmits to RF interface |
                                          +-------------------------------+
```

---

## Execution & Teardown Lifecycle

1. **Initialization**: `cli.main()` resolves parameters, initializes `DroneState` instances, and instantiates the selected transport backends.
2. **Start**: `DroneSpoofer` invokes `backend.start(drones, packet_builder)` on all backends, spawning independent transmission daemon threads.
3. **Execution**: The main thread advances drone kinematics (positions, headings, altitudes, timers) every interval tick. Background threads continuously pull the latest state and transmit over raw sockets.
4. **Shutdown**: On `SIGINT` (Ctrl+C) or when all drones exceed their lifespan, `DroneSpoofer` runs `backend.close()` on all backends, disabling advertising sets, shutting down sockets, and terminating background threads gracefully.
