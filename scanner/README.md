# Drone Remote ID Scanner & Persistent Flight Logger (`scanner/`)

A high-performance, combined **Bluetooth (BLE 4/5 via nRF UART)** and **Wi-Fi (Beacon & NAN via multi-band Channel Hopping)** Drone Remote ID (RID) listener, telemetry decoder, and persistent flight logger.

Compliant with **ASTM F3411-19**, **ASTM F3411-22**, and **ASD-STAN (OpenDroneID)** standards.

---

## Table of Contents
- [1. Architecture Overview](#1-architecture-overview)
- [2. Hardware & Software Requirements](#2-hardware--software-requirements)
- [3. Wi-Fi Channel Hopping Specification](#3-wi-fi-channel-hopping-specification)
- [4. Dual Logging & Flight Encounter Engine](#4-dual-logging--flight-encounter-engine)
- [5. How to Run the Scanner (`combined_rid_listener.py`)](#5-how-to-run-the-scanner-combined_rid_listenerpy)
- [6. Querying & Exporting Flights (`query_rid_db.py`)](#6-querying--exporting-flights-query_rid_dbpy)
- [7. Replaying Captured Traffic (`replay_drones.py`)](#7-replaying-captured-traffic-replay_dronespy)
- [8. Running the Unit Tests](#8-running-the-unit-tests)

---

## 1. Architecture Overview

The scanner coordinates three concurrent threads into a non-blocking ingestion and logging pipeline:

```mermaid
graph TD
    subgraph Bluetooth Subsystem
        nRF_HW[nRF52840 Dongle / DevKit] -->|UART Serial Stream| nRF_Process[nrf_bt_sniffer_json.py Subprocess]
        nRF_Process -->|JSON Stream stdout| Ble_Thread[BleNrfSnifferThread]
    end

    subgraph Wi-Fi Subsystem
        Hopper_Thread[WifiChannelHopperThread] -->|iw / nl80211 Channel Switching| WLAN[Wi-Fi Interface in Monitor Mode]
        Hopper_Thread -.->|Active Channel & Band State| SharedState[(Shared ChannelState)]
        WLAN -->|AF_PACKET Raw 802.11 Socket| WiFi_Thread[WifiSnifferThread]
        SharedState -.->|Tag Channel / Freq| WiFi_Thread
    end

    subgraph Unified Logging Pipeline
        Ble_Thread -->|Normalized Event| EventQueue[Thread-Safe Event Queue]
        WiFi_Thread -->|Normalized Event| EventQueue
        EventQueue --> Logger[Unified Telemetry Logger]
        Logger -->|1. Live Stream| Console[Colorized Terminal Display]
        Logger -->|2. Append & Flush| JSONL[Replay JSONL Log (.jsonl)]
        Logger -->|3. 5-Min Timeout| SQLite[(SQLite Encounters DB: rid_detections.db)]
    end
```

### Thread Responsibilities
1. **`WifiChannelHopperThread`**: Executes the precise multi-band 2.4 GHz / 5.8 GHz hopping schedule with dedicated intraband (30ms) and interband (50ms) switching delays.
2. **`WifiSnifferThread`**: High-throughput Linux `AF_PACKET` raw socket capture parsing 802.11 Beacons (Vendor Specific IE `0xDD` / OUI `FA:0B:BC` / AppCode `0x0D`) and Wi-Fi NAN Action frames.
3. **`BleNrfSnifferThread`**: Autonomous driver managing `nrf_bt_sniffer_json.py` over UART to capture BLE 4 Legacy and BLE 5 Extended Remote ID advertisements.
4. **`UnifiedTelemetryLogger`**: Drains the event queue to print colorized real-time telemetry, append to a replay-compatible `.jsonl` log, and update the 5-minute SQLite flight encounter tracker.

---

## 2. Hardware & Software Requirements

### Hardware
1. **Wi-Fi Adapter with Monitor Mode & Dual-Band (2.4 GHz + 5.8 GHz) Support**:
   - e.g. Alfa AWUS036ACH (RTL8812AU), MediaTek MT7612U / MT7921, or Atheros AR9271.
2. **Nordic Semiconductor nRF52840 Dongle / DevKit**:
   - Flashed with Nordic's nRF BLE Sniffer firmware connected via USB (e.g. `/dev/ttyACM0`).

### Software Dependencies
- Linux OS with `iw`, `iproute2`, and root/sudo privileges (for monitor mode and raw sockets).
- Python 3.9+ with `scapy` and standard libraries.

---

## 3. Wi-Fi Channel Hopping Specification

The scanner implements an optimized ASTM F3411 hopping sequence ensuring regular coverage of social channels while systematically sweeping non-social channels across both bands.

### Channel Allocation & Dwell Times
- **2.4 GHz Band**:
  - **Social Channel (1 Hz Dwell)**: Channel `6` $\to$ **1000 ms**
  - **Non-Social Channels (5 Hz Dwell)**: Channels `1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13` $\to$ **200 ms** each
- **5.8 GHz Band (5725 – 5875 MHz)**:
  - **Social Channel (1 Hz Dwell)**: Channel `149` $\to$ **1000 ms**
  - **Non-Social Channels (5 Hz Dwell)**: Channels `153, 157, 161, 165, 169, 173` $\to$ **200 ms** each

### Switching Latency Overhead & Tunability
- **Intraband Switching Delay (Default: `30 ms`)**: Delay when hopping within the same band (e.g. $2.4\text{ GHz} \to 2.4\text{ GHz}$ or $5.8\text{ GHz} \to 5.8\text{ GHz}$).
- **Interband Switching Delay (Default: `50 ms`)**: Delay when crossing frequency bands (e.g. $2.4\text{ GHz} \to 5.8\text{ GHz}$ or $5.8\text{ GHz} \to 2.4\text{ GHz}$).

> [!NOTE]
> **Switching Latency is an Empirical Estimate**:
> Exact channel switching latency varies across Wi-Fi chipsets (e.g. RTL8812AU vs MT7921 vs AR9271), Linux wireless drivers, and USB bus overhead. The default values (`30 ms` intraband, `50 ms` interband) are conservative baseline estimates and are **fully configurable via CLI flags**:
> - `--intraband-delay-ms <ms>` (e.g. `--intraband-delay-ms 20`)
> - `--interband-delay-ms <ms>` (e.g. `--interband-delay-ms 40`)
> - `--social-dwell-ms <ms>` (default `1000`)
> - `--non-social-dwell-ms <ms>` (default `200`)

### Configurable $2k:k$ Ratio (Default $k=1$)
In every cycle, the hopper sweeps:
1. **2.4 GHz Social (Ch 6)**: 1000 ms dwell
2. **2.4 GHz Non-Social ($2k$ channels, e.g. 2)**: 200 ms dwell + 30 ms switch each
3. **5.8 GHz Social (Ch 149)**: 1000 ms dwell + 50 ms switch
4. **5.8 GHz Non-Social ($k$ channels, e.g. 1)**: 200 ms dwell + 30 ms switch

```
Cycle 1: Ch 6 (1000ms) -> Ch 1, Ch 2 (200ms) -> Ch 149 (1000ms) -> Ch 153 (200ms)
Cycle 2: Ch 6 (1000ms) -> Ch 3, Ch 4 (200ms) -> Ch 149 (1000ms) -> Ch 157 (200ms)
Cycle 3: Ch 6 (1000ms) -> Ch 5, Ch 7 (200ms) -> Ch 149 (1000ms) -> Ch 161 (200ms)
Cycle 4: Ch 6 (1000ms) -> Ch 8, Ch 9 (200ms) -> Ch 149 (1000ms) -> Ch 165 (200ms)
Cycle 5: Ch 6 (1000ms) -> Ch 10, Ch 11 (200ms) -> Ch 149 (1000ms) -> Ch 169 (200ms)
Cycle 6: Ch 6 (1000ms) -> Ch 12, Ch 13 (200ms) -> Ch 149 (1000ms) -> Ch 173 (200ms)
```
*(All 18 channels across both bands are fully scanned every 6 cycles / ~16.74 seconds!)*

---

## 4. Dual Logging & Flight Encounter Engine

```
[Raw Broadcasts] ---> Live Console Feed
                 ---> Replay-Ready JSONL Stream (.jsonl)
                 ---> 5-Minute Inactivity Timeout ---> SQLite Encounters Table (.db)
```

1. **Replay-Compatible JSONL (`.jsonl`)**:
   - Contains raw `messages_b64` (25-byte base64 chunks), `time_offset_ms`, `counter`, `transport`, `mac`, and `serial`.
   - **Direct drop-in for `replay_drones.py`**.
2. **SQLite Database (`rid_detections.db`)**:
   - Contains the `encounters` table aggregating drone sightings into distinct flight sessions.
   - Automatically tracks:
     - `encounter_id`: e.g. `ENC-20260825-141510-AABBCC`
     - Start time, End time, Duration
     - Total packet count and active physical transports (`ble5`, `wifi`, etc.)
     - Signal strength profile (Min, Max, Avg RSSI)
     - Altitude range (Min & Max altitude) and Max ground speed
     - Pilot coordinates, Operator ID, Self-ID description
     - Full coordinate flight trajectory (`[[lat, lon, alt, speed, heading, ts], ...]`)
   - **5-Minute Timeout**: If no packets are received from a drone for **300 seconds (5 minutes)**, the encounter is marked closed (`is_active = 0`). Any subsequent detection starts a new encounter.

---

## 5. How to Run the Scanner (`combined_rid_listener.py`)

### 1. Standard Combined Wi-Fi + BLE Mode
```bash
sudo python3 scanner/combined_rid_listener.py \
    --wifi-iface wlan1 \
    --nrf-port /dev/ttyACM0 \
    --db-file rid_detections.db \
    --log-jsonl capture.jsonl
```

### 2. Wi-Fi Only (Custom Hopping Ratio Multiplier $k=2$)
```bash
sudo python3 scanner/combined_rid_listener.py \
    --wifi-iface wlan1 \
    --no-ble \
    -k 2 \
    --db-file rid_wifi_only.db
```

### 3. BLE 5 Extended Mode (Default BLE Behavior)
```bash
python3 scanner/combined_rid_listener.py \
    --no-wifi \
    --db-file rid_ble5_only.db
```
*(BLE 5 Extended Advertising and LE Coded PHY tracking are active by default. Port `/dev/ttyACM0` is auto-detected.)*

### 4. Running as a 24/7 Background Service (systemd)
The scanner includes a dedicated systemd service template [`scanner/drone-scanner.service`](file:///home/davidalexander/ETH/droneID_thesis/droneRemoteIDSpoofer/scanner/drone-scanner.service) configured for autonomous, indefinite operation:

```bash
# 1. Copy service file to systemd directory
sudo cp scanner/drone-scanner.service /etc/systemd/system/

# 2. Reload daemon and start service
sudo systemctl daemon-reload
sudo systemctl enable --now drone-scanner.service

# 3. View live heartbeat and status
sudo systemctl status drone-scanner.service
sudo journalctl -u drone-scanner.service -f
```

### CLI Arguments Reference

| Argument | Default | Description |
| :--- | :--- | :--- |
| `--wifi-iface`, `-i` | `None` | Wi-Fi monitor-mode interface (e.g. `wlx00c0cabd0a22` or `wlan1`) |
| `--nrf-port`, `-p` | `None` (auto) | nRF Sniffer UART port (e.g. `/dev/ttyACM0`). Auto-reconnects on USB disconnect. |
| `--no-wifi` | `False` | Disable Wi-Fi sniffing and channel hopping |
| `--no-ble` | `False` | Disable Bluetooth sniffing |
| `--no-wifi-setup` | `False` | Skip bringing Wi-Fi interface down/up into monitor mode |
| `--wifi-channel`, `-c` | `None` | Lock Wi-Fi sniffer to a single fixed channel (e.g. 6 or 149) |
| `--no-hop` | `False` | Disable Wi-Fi channel hopping (listen on initial channel) |
| `--non-social-ratio`, `-k` | `1` | Ratio multiplier ($2k$ non-social on 2.4 GHz per $k$ on 5.8 GHz) |
| `--social-dwell-ms` | `1000` | Social channel dwell time in milliseconds (1 Hz) |
| `--non-social-dwell-ms` | `200` | Non-social channel dwell time in milliseconds (5 Hz) |
| `--intraband-delay-ms` | `30` | Intraband switching delay in milliseconds |
| `--interband-delay-ms` | `50` | Interband switching delay in milliseconds |
| `--coded` | `False` | Enable BLE 5 Long Range (LE Coded PHY) scanning |
| `--ble-mode` | `extended` | Filter BLE advertisements: `extended` (BLE 5 Extended Advertising), `legacy` (BLE 4), `all` |
| `--db-file` | `rid_detections.db` | SQLite database path for flight encounters (`''` to disable) |
| `--encounter-timeout-s` | `300.0` | Inactivity timeout in seconds before closing an encounter (5 min) |
| `--persist-interval` | `2.0` | Max frequency in seconds to persist active encounters to SQLite |
| `--log-jsonl` | `None` | Optional output JSONL replay file path |
| `--rotate-daily` | `False` | Automatically split JSONL log file daily (`<path>_YYYYMMDD.jsonl`) |
| `--quiet`, `-q` | `False` | Quiet mode: suppress per-packet terminal banner and print 30s status heartbeat |

---

## 6. Querying & Exporting Flights (`query_rid_db.py`)

The companion tool [`query_rid_db.py`](file:///home/davidalexander/ETH/droneID_thesis/droneRemoteIDSpoofer/scanner/query_rid_db.py) provides instant search, table formatting, and GeoJSON export for all flights in the SQLite database:

### 1. List Recorded Flights
```bash
# List all encounters
python3 scanner/query_rid_db.py list

# Search flights by UAS Serial Number or MAC
python3 scanner/query_rid_db.py list --serial "DJI_MINI" --since "2026-08-20"

# List currently active flights in progress
python3 scanner/query_rid_db.py list --active-only
```

*Example Output:*
```
🚁 RECORDED DRONE FLIGHT ENCOUNTERS (2 found)
Database: rid_detections.db

ENCOUNTER ID               START TIME (UTC)    DURATION   PKTS   MAC                SERIAL / UAS ID        TRANSPORTS     MAX ALT   STATUS  
--------------------------------------------------------------------------------------------------------------------------------------------
ENC-20260825-135320-C09EB6 2026-08-25 13:53:20 4m 12s     142    E4:D8:FC:C0:9E:B6  AUTEL_EVO_99           wifi           120.5m    CLOSED
ENC-20260825-133640-AABBCC 2026-08-25 13:36:40 2m 45s     98     60:60:1F:AA:BB:CC  DJI_MINI4_001          bt5            95.0m     CLOSED
--------------------------------------------------------------------------------------------------------------------------------------------
```

### 2. Inspect Flight Details
```bash
# Lookup by Encounter ID, Serial Number, or MAC
python3 scanner/query_rid_db.py show DJI_MINI4_001
```

### 3. Export Trajectory to GeoJSON (Map Visualization)
```bash
python3 scanner/query_rid_db.py export-geojson DJI_MINI4_001 -o flight.geojson
```
> [!TIP]
> Drag and drop `flight.geojson` directly into **[geojson.io](https://geojson.io)**, Google Earth, or QGIS to visualize the flight path, start/end locations, and pilot home position!

### 4. Export Trajectory Points to CSV
```bash
python3 scanner/query_rid_db.py export-csv DJI_MINI4_001 -o flight_points.csv
```

### 5. Airspace Statistics Summary
```bash
python3 scanner/query_rid_db.py stats
```

---

## 7. Replaying Captured Traffic (`replay_drones.py`)

Any JSONL file recorded with `--log-jsonl <capture.jsonl>` can be replayed over the air using the spoofer's replay engine:

```bash
# Replay captured broadcast traffic over Wi-Fi and Bluetooth
sudo python3 replay/replay_drones.py capture.jsonl --wifi-iface wlan1 --ble-adapter hci0
```

---

## 8. Decoded Message Types & Fields Reference

The scanner comprehensively extracts and decodes all standard ASTM F3411 / OpenDroneID message types:

| Type ID | Message Name | Decoded Fields & Accuracy Indicators |
| :--- | :--- | :--- |
| **`0x0`** | **Basic ID** | `id` (UAS ID string), `id_type` (`Serial Number`, `CAA Registration`, `UUID`, `Session ID`), `ua_type` (`Multirotor`, `Fixed Wing`, `VTOL`, etc.), `proto_version` |
| **`0x1`** | **Location / Vector** | `status` (`Ground`, `Airborne`, `Emergency`, `System Failure`), `lat`/`lon`, `direction_deg`, `speed_mps`, `vertical_speed_mps`, `geodetic_altitude_m`, `pressure_altitude_m`, `height_m`, `height_type` (`Above Takeoff` vs `AGL`), `horizontal_accuracy` (e.g. `< 1m`, `< 3m`, `< 10m`), `vertical_accuracy`, `baro_accuracy`, `speed_accuracy`, `timestamp_s` |
| **`0x2`** | **Authentication** | `auth_type` (`UAS ID Signature`, `Operator ID Signature`, `Message Set Signature`, `Network RID`, `Specific Auth`), `page_number` (`0..15`), `last_page_index`, `auth_data_length`, `auth_timestamp_iso`, `auth_data_hex` |
| **`0x3`** | **Self-ID** | `desc_type` (`Text`, `Emergency Status`, `Extended Status`), `description` |
| **`0x4`** | **System** | `pilot_lat`/`pilot_lon`, `pilot_alt_m`, `operator_location_type` (`Takeoff`, `Live GNSS`, `Fixed`), `area_count`, `area_radius_m`, `area_ceiling_m`, `area_floor_m`, `classification_type` (`EU`), `category_eu` (`Open`, `Specific`, `Certified`), `class_eu` (`Class 0`..`Class 6`), `system_timestamp_iso` |
| **`0x5`** | **Operator ID** | `operator_id` (e.g. `CHE-123456789abc-xyz`), `operator_id_type` |
| **`0xF`** | **Message Pack** | Decompresses 25-byte composite packs into individual typed sub-messages |

---

## 9. Running the Unit Tests

Automated test suites verify ASTM decoding, hopping schedule math, SQLite persistence, and replay formatting:

```bash
python3 -m unittest scanner.test_combined_rid_listener scanner.test_db_logging
```

