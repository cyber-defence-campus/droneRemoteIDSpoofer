# Modular ESP32 Remote ID Spoofer / Broadcast Transmitter

An ESP-IDF (v5.x / v6.x) C-based implementation for broadcasting ASTM F3411 Remote ID (ODID) telemetry across multiple RF backends (Wi-Fi Beacons, BLE 4 Legacy, BLE 5 Extended Coded PHY, and Wi-Fi Aware / NAN).

This project features a hardware GPS ingestion module that parses live NMEA sentences from an **Adafruit Ultimate GPS Breakout v3** via UART to update ASTM Location and Vector telemetry in real time.

---

## Hardware Setup & Pinout

### Recommended Target Hardware
- **MCU**: ESP32-C5 (or ESP32-C3 / ESP32-S3 / standard ESP32) DevKit
- **GPS Module**: Adafruit Ultimate GPS Breakout v3 (MTK3339 chipset)

### Wiring Diagram (UART1)

The GPS reader task uses **UART1** at **9600 baud (8N1)** to receive NMEA sentences (`$GPRMC`, `$GPGGA`, `$GNRMC`, `$GNGGA`).

| Adafruit GPS Breakout v3 Pin | ESP32-C5 DevKit Pin | Function / Notes |
|------------------------------|----------------------|------------------|
| **VIN**                      | **3.3V**             | Power Input |
| **GND**                      | **GND**              | Common Ground |
| **TX**                       | **GPIO 12**          | ESP32 UART1 RXD (`GPS_UART_RXD`) |
| **RX**                       | **GPIO 11**          | ESP32 UART1 TXD (`GPS_UART_TXD`) |
| **FIX**                      | *Optional*           | Pulse indicator (1 Hz fix / 15s search) |

> **Note**: Pin definitions can be adjusted in `components/gps_reader/gps_reader.c`:
> ```c
> #define GPS_UART_PORT_NUM      UART_NUM_1
> #define GPS_UART_BAUD_RATE     9600
> #define GPS_UART_TXD           (11) 
> #define GPS_UART_RXD           (12) 
> ```

---

## Technical Architecture

The firmware utilizes a decoupled Producer-Consumer pattern:

1. **Producer Task (`gps_task`)**: Continually reads raw NMEA strings from UART1, extracts latitude, longitude, altitude, speed, and course over ground (COG), packs them into standard `opendroneid_location_msg_t` binary structures, and updates shared thread-safe memory guarded by a FreeRTOS mutex.
2. **Consumer Task (Transport Backend)**: Periodically reads the latest location structure and broadcasts formatted ASTM F3411 payloads over the selected wireless medium.

---

## Project Configuration & `sdkconfig` Flags

Configuration is managed via ESP-IDF `menuconfig` or `sdkconfig.defaults`. Run `idf.py menuconfig` to access project options under **"Remote ID Transport Layer"**.

### 1. Custom Project Configuration Flags (`Kconfig.projbuild`)

| Kconfig Symbol | Selection / Default | Description |
|----------------|---------------------|-------------|
| `CONFIG_TRANSPORT_SELECTION` | `choice` | Select active RF transport layer |
| `CONFIG_TRANSPORT_DUMMY` | `y` *(default)* | Dummy/Serial transport (logs payloads to UART console) |
| `CONFIG_TRANSPORT_BLE` | `bool` | **BLE 5 Extended Advertising** (Coded PHY / ODID Message Pack) |
| `CONFIG_TRANSPORT_BLE4` | `bool` | **BLE 4 Legacy Advertising** (`ADV_NONCONN_IND` message rotation) |
| `CONFIG_TRANSPORT_NAN` | `bool` | **Wi-Fi Aware (NAN)** Action Frames & Discovery Beacons |
| `CONFIG_TRANSPORT_WIFI_BEACON` | `bool` | **Wi-Fi Raw Beacon Injection** (Vendor IE 0xFA0BBC) |
| `CONFIG_DRONE_NAME` | `"VHCI_SPOOFER12345678"` | Drone serial number for Basic ID (max 20 chars) |
| `CONFIG_OPERATOR_ID` | `"CH-1234567890123456"` | Operator ID string (max 20 chars) |
| `CONFIG_SELF_ID` | `"Spoofing test"` | Self ID text payload (max 23 chars) |
| `CONFIG_WIFI_CHANNEL` | `6` (range 1-14) | Wi-Fi channel for Beacon and NAN transmissions |
| `CONFIG_BEACON_INTERVAL_TU` | `100` TU (102.4 ms) | Transmission interval for Wi-Fi Beacons (1 TU = 1.024 ms) |
| `CONFIG_NAN_CLUSTER_ID` | `"50:6F:9A:01:00:FF"` | Wi-Fi Alliance NAN Cluster MAC / BSSID address |
| `CONFIG_BLE4_INTERVAL_MS` | `100` ms | Repetition interval for BLE 4 legacy advertisement rotation |
| `CONFIG_GPS_DUMMY_TEST_MODE` | `n` *(default)* | When `y`, provides simulated Zurich coordinates if physical GPS fix is absent |

---

### 2. Critical ESP-IDF Framework Defaults (`sdkconfig.defaults`)

To support high-throughput BLE Extended Advertising and Wi-Fi NAN sync, the following controller and stack configurations must be enabled in `sdkconfig.defaults`:

```ini
# Enable Bluetooth Controller in LE Mode
CONFIG_BT_ENABLED=y
CONFIG_BT_CONTROLLER_ONLY=y
CONFIG_BT_CLASSIC_ENABLED=n
CONFIG_BT_NIMBLE_ENABLED=n
CONFIG_BT_BLUEDROID_ENABLED=n

# CRITICAL for Extended Advertising (BLE 5 Coded PHY)
# The controller must allocate memory for EA instances!
CONFIG_BT_LE_MAX_EXT_ADV_INSTANCES=4

# CRITICAL for Wi-Fi Aware (NAN) Transport
CONFIG_ESP_WIFI_NAN_ENABLE=y
CONFIG_ESP_WIFI_NAN_SYNC_ENABLE=y
```

---

## Build & Flash Instructions

### Prerequisites
- Espressif ESP-IDF v5.x or v6.x environment configured (`export.sh` sourced).

### Step-by-Step Setup

1. **Set Target Microcontroller**:
   ```bash
   idf.py set-target esp32c5
   ```

2. **Configure Spoofer Options**:
   ```bash
   idf.py menuconfig
   ```
   Navigate to `Remote ID Transport Layer` to pick your target RF backend (BLE 5, BLE 4, Wi-Fi Beacon, or NAN) and configure serial/operator IDs.

3. **Build the Project**:
   ```bash
   idf.py build
   ```

4. **Flash and Monitor Output**:
   ```bash
   idf.py -p /dev/ttyUSB0 flash monitor
   ```

---

## Testing Modes

- **Physical GPS Mode (`CONFIG_GPS_DUMMY_TEST_MODE=n`)**:
  - Connect the Adafruit Ultimate GPS breakout.
  - The `GPS_READER` task waits for a valid 3D GPS fix (`$GPRMC` status `A`).
  - Upon receiving a valid fix, live telemetry is packed and handed off to the active transport.
- **Simulated Test Mode (`CONFIG_GPS_DUMMY_TEST_MODE=y`)**:
  - Useful for indoor lab testing without outdoor GPS satellite visibility.
  - If no physical fix is acquired, fallback coordinates (Lat: `47.3777344 N`, Lon: `8.5526392 E`, Altitude: `450m`) are automatically supplied to the transmitter.
