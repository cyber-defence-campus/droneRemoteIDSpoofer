# Drone Remote ID Spoofer - Bluetooth and WiFi Beacon



A tool for crafting and transmitting spoofed drone Remote ID (RID) packets compliant with ASTM F3411-19/22, supporting WiFi Beacon and BLE. Built for **security researchers**, **drone detection system developers**, and anyone studying the robustness of the Remote ID protocol. The protocol itself does not provide authentication or cryptographic integrity, which makes it inherently vulnerable to message injection or impersonation in uncontrolled environments.

It generates raw 802.11 beacon frames and BLE advertisements containing ASTM F3411 message payloads, making fake drones appear on any compliant receiver — OpenDroneID apps, DroneTag Rider, DJI AeroScope, and custom monitoring systems.

### Features

- **Multi-transport** — Wi-Fi beacon frames, BLE advertisements, and Wi-Fi NAN (Aware), individually or simultaneously
- **Multi-drone** — spoof several DroneIDs at once, each with unique serial, MAC, and flight behavior
- **Flight modes** — random walk, static position, or predefined waypoint paths
- **Scenario configs** — define multi-drone scenarios in JSON (10+ ready-to-use examples included)
- **Manual control** — spoof a DroneID location in real-time with WASD keyboard input

### Use cases

- Testing and validating drone detection / monitoring systems (see our [RemoteIDReceiver](https://github.com/cyber-defence-campus/RemoteIDReceiver) for WiFi beacon)
- Security research on Remote ID protocol weaknesses
- Stress-testing receiver capacity and performance
- Developing and debugging RID-aware applications

---

## Quick Start

### Requirements

| Transport | Hardware | Software |
|-----------|----------|----------|
| **Wi-Fi** | 802.11 adapter supporting monitor mode | Linux, root, `scapy` |
| **BLE**   | Bluetooth adapter (HCI) | Linux, root |
| **NAN (Manual)** | 802.11 adapter supporting monitor mode | Linux, root, direct raw injection (no phone required) |
| **NAN (Bridge)** | Android device with Wi-Fi Aware | Android App (`NaN_Bridge`), ADB |

### Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .          # add [dev] for pytest/build tooling
```

> **Tip — tab-completion**
>
> Install bash completion for the `drone-spoofer` command (interface names after
> `-i`, Wi-Fi channels after `--wifi-channel`, BLE adapters, transport/mode choices):
> ```bash
> ./completion/install-completion.sh      # add sudo to also install system-wide
> ```
> Then restart your shell. Since the spoofer needs root, use the entry point by
> path so completion fires *and* sudo's `secure_path` is bypassed:
> ```bash
> sudo .venv/bin/drone-spoofer -i <tab>
> ```
> (It also completes for `drone-spoofer …` without sudo.) To load completion for
> the current shell only: `source completion/drone-spoofer.bash`.

### Run your first spoof - Single drone

**Wi-Fi** — just point the spoofer at your adapter; it configures monitor mode
(on the target channel) itself and restores managed mode on exit:
```bash
sudo .venv/bin/python3 spoof_drones.py -i <interface-name>
```

> **Important — Legal Compliance & Wi-Fi Regulatory Domain**
>
> When conducting wireless experiments, **users are solely responsible for ensuring all transmissions strictly comply with local telecommunications, radio spectrum, and aviation regulations.**
>
> On Linux, the wireless regulatory domain enforces the legal frequency bands, authorized channels, and maximum transmit power (EIRP) limits for your physical location:
> - **Always set the regulatory domain to match your actual geographic jurisdiction**:
>   ```bash
>   sudo iw reg set <YOUR-LOCAL-COUNTRY-CODE>   # e.g., CH (Switzerland), DE (Germany), US, etc.
>   ```
> - **Do NOT set an arbitrary or foreign regulatory domain** simply to circumvent local frequency restrictions, radar detection (DFS) rules, or transmission bans on specific channels (such as 5.8 GHz channels 149–165). Transmitting on unauthorized frequencies or exceeding local power limits violates national radio laws.
> - You can verify your active channel permissions, DFS requirements, and power limits at any time using `iw reg get`.

**BLE** — make sure your adapter is up:
```bash
sudo rfkill unblock all
sudo hciconfig hci0 up
sudo .venv/bin/python3 spoof_drones.py -t ble --ble-adapter hci0
```

**Both at once:**
```bash
sudo .venv/bin/python3 spoof_drones.py -i wlan1 -t both --ble-adapter hci0
```

**Wi-Fi NAN (Wi-Fi Aware):**

*Option A — Direct Linux Raw Packet Injection (Manual Mode - No Android device required):*
Injects IEEE 802.11 Wi-Fi Aware Action Frames and Discovery Beacons directly from a monitor mode interface:
```bash
sudo .venv/bin/python3 spoof_drones.py -t nan --nan-mode manual -i wlan1
```

*Option B — Android Bridge App (Bridge Mode):*
1. Install and run the `NaN_Bridge` app on an Android device supporting Wi-Fi Aware.
2. Connect device via ADB and forward the TCP port:
```bash
adb forward tcp:8080 tcp:8080
```
3. Run the spoofer with `nan` transport in bridge mode:
```bash
python3 spoof_drones.py -t nan --nan-mode bridge --nan-port 8080
```

You should see the spoofed drone appear on any RID receiver within range.

<img src="./resources/images/spoofed_mobile_app.jpeg" alt="droneScanner app" width="200" style="margin-right:10px;"/><img src="./resources/images/spoofed_remote_id.png" alt="Remote Drone ID Receiver" width="450"/>

*DroneTag iOS application and RemoteIDReceiver spoofed.*

**Note**
- On Google Pixel 9 we could only spoof the *OpenDroneID* app but not the *DroneTag* via BLE.


---

## Examples

### Scenario file

```bash
sudo python3 spoof_drones.py -c scenarios/single_random.json
```

### Drone swarm (5 drones)

```bash
sudo python3 spoof_drones.py -i wlan1 -r 5
```

### Manual keyboard control

```bash
sudo python3 spoof_drones.py -i wlan1 -m
```
Use **W/A/S/D** to fly north/west/south/east, **Ctrl+C** to stop.

### Waypoint flight path

```bash
sudo python3 spoof_drones.py -c scenarios/flight_path.json
```

### Stress test (20 drones)

```bash
sudo python3 spoof_drones.py -c scenarios/stress_test.json
```

See the `scenarios/` directory for all ready-to-use configs, or create your own — full reference in [CONFIG.md](CONFIG.md).

---

## How it works

```
Scenario JSON / CLI args
        |
        v
  +-----------+       +------------------+
  |  Spoofer  | ----> | build_basic_id   |  25-byte ASTM payloads
  |  Loop     |       | build_location   |  (identical across
  |           |       | build_system     |   transports)
  |           |       | build_operator   |
  +-----------+       +------------------+
        |
        v
  +-----+------+
  |            |
  v            v
Wi-Fi        BLE
Backend      Backend
  |            |
  v            v
Dot11        HCI raw
Beacon       ADV_NONCONN_IND
(scapy)      (socket)
```

Each cycle, the spoofer builds 4 ASTM F3411 message payloads per drone (Basic ID, Location, System, Operator ID) and hands them to each active transport backend. The backends wrap the same payloads in their respective frame formats and transmit.

For full architecture details, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## CLI Reference

| Flag | Long form | Parameter | Default | Description |
|------|-----------|-----------|---------|-------------|
| `-i` | `--interface` | `str` | config or `wlan1` | Wi-Fi interface for injection |
| `-m` | `--manual` | - | - | Manual mode (WASD keyboard control) |
| `-r` | `--random` | `int` | config or `1` | Number of random drones |
| `-s` | `--serial` | `str` | random | Custom serial (max 20 chars) |
| `-n` | `--interval` | `float` | config or `1.0` | Seconds between packet batches |
| `-l` | `--location` | `lat lng` | config or Zurich | Base coordinates (decimal degrees) |
| `-c` | `--config` | `path` | - | Path to scenario JSON config |
| `-v` | `--verbose` | - | - | Enable debug logging |
| `-t` | `--transport` | `wifi\|ble\|nan\|both\|all` | config or `wifi` | Transport backend |
| | `--no-self-id` | - | - | Omit Self ID payload to optimize frame airtime |
| | `--ble-adapter` | `str` | config or `hci0` | BLE HCI adapter name |
| | `--ble-interval` | `int` | `200` | BLE 4 legacy advertising interval (ms) |
| | `--ble-extended-interval` | `int` | same as legacy | BLE 5 extended advertising interval (ms) |
| | `--ble-mode` | `extended\|ext-legacy\|legacy\|dual` | `extended` | BLE transmission mode (`extended`=Coded PHY, `ext-legacy`=BLE4 via Ext HCI, `legacy`=classic HCI, `dual`=both) |
| | `--wifi-channel`| `int` | config or `6` | Wi-Fi channel for injection |
| | `--wifi-ess` | - | - | Set ESS capability (make beacon look like an AP) |
| | `--wifi-beacon-interval` | `float` | config or `0.1024` | Wi-Fi beacon transmission interval in seconds |
| | `--nan-mode` | `bridge\|manual` | config or `bridge` | NAN mode: Android TCP bridge or direct Linux raw injection |
| | `--nan-port` | `int` | config or `8080` | TCP port for the NAN Android Bridge |
| | `--nan-cluster-id` | `str` | `50:6f:9a:01:00:00` | NAN Cluster BSSID MAC for manual injection |
| | `--nan-instance-id` | `int/hex` | `0x10` | NAN Service Instance ID for manual injection |

**Single-drone overrides** (applied to the drone in manual mode, or the first drone in automatic mode; the remaining random drones are unaffected). These let you fully configure one drone from the CLI without a scenario JSON:

| Flag | Parameter | Default | Description |
|------|-----------|---------|-------------|
| `--mac` | `str` | random LAA | Wi-Fi MAC address |
| `--ble-mac` | `str` | random static-random | BLE advertising address |
| `--operator` | `str` | none | Operator ID (max 20 chars) |
| `--description` | `str` | none | Self-ID text description (max 23 chars) |
| `--lifespan` | `float` | `0` (forever) | Seconds before the drone stops transmitting |
| `--static` | - | - | Keep the drone stationary (no random drift) |
| `--pilot-location` | `lat lng` | near drone | Pilot/operator coordinates (decimal degrees) |
| `--timestamp-offset` | `float` | `0` | Minutes to shift the ASTM timestamp (negative = past) |
| `--speed` | `float` | random | Horizontal speed (m/s) |
| `--vertical-speed` | `float` | random | Vertical speed (m/s, + = climbing) |
| `--geodetic-altitude` | `float` | random | Geodetic altitude (m MSL) |
| `--pressure-altitude` | `float` | tracks geodetic | Pressure altitude (m MSL) |
| `--height` | `float` | random | Height above takeoff (m) |

For multiple precisely-configured drones, per-drone arrays, or waypoint flight paths, use a scenario JSON ([CONFIG.md](CONFIG.md)).

CLI flags override values from scenario config files.

---

## Advanced Security Research & Evaluation Suite

In addition to `spoof_drones.py`, the repository includes specialized security evaluation, fuzzing, scanning, and takeover modules:

- **Capacity & RF Benchmarking Suite (`evaluation/`)**: Automated multi-mode benchmark orchestrator (`run_ble_benchmark.py`), Wi-Fi capacity tester (`wifi_capacity.py`), and BLE capacity tester (`ble_capacity.py`) with unified plotting engine (`plot_capacity.py`, `plot_ble_comparisons.py`). See [evaluation/README.md](evaluation/README.md).
- **Offensive Security Attacks & Exploit Verification (`attacks/`)**: Comprehensive suite containing real-time drone session takeover (`attacks/takeover/`), EASA registration checksum collision solver (`attacks/protocol/`), ephemeral swarm identity flood (`attacks/ephemeral_swarm.py`), and OTA protocol mutation fuzzer (`attacks/fuzz_rid.py`). See [attacks/README.md](attacks/README.md).
- **PCAP Replay Engine (`replay/`)**: Replay captured raw 802.11 / BLE Remote ID telemetry from PCAP recordings (`replay/replay_drones.py`).

For comprehensive experiment workflows, parameter guides, and command examples, see the [EXPERIMENT_GUIDE.md](EXPERIMENT_GUIDE.md).

---

## Scenario configs

Scenarios are JSON files that define global settings and one or more drones. A minimal example:

```json
{
  "global": { "interface": "wlan1" },
  "drones": [ { "mode": "random" } ]
}
```

Each drone can have its own mode (`random`, `static`, `waypoints`), serial, MAC, location, lifespan, and transport override. See [CONFIG.md](CONFIG.md) for the full reference and [scenario.template.json](scenario.template.json) for a copyable template.

### Included scenarios

| File | Description |
|------|-------------|
| `single_random.json` | One random drone (Wi-Fi) |
| `swarm_random.json` | 5-drone swarm (Wi-Fi) |
| `flight_path.json` | Waypoint flight with hold times |
| `timed_appearance.json` | Drones that appear and vanish |
| `airport_incursion.json` | Simulated airport incursion |
| `ble_single.json` | One random drone (BLE) |
| `ble_swarm.json` | 5-drone swarm (BLE) |
| `ble_stress_test.json` | 20 drones over BLE |
| `dual_transport.json` | Wi-Fi + BLE simultaneously |
| `stress_test.json` | 20 drones over Wi-Fi |

---

## Related projects

- [RemoteIDReceiver](https://github.com/cyber-defence-campus/RemoteIDReceiver) — our drone monitoring system, designed to be tested with this spoofer
- [OpenDroneID](https://github.com/opendroneid) — open-source Remote ID implementations and Android receiver app
- [ASTM F3411-22a](https://www.astm.org/f3411-22a.html) — the Remote ID standard this tool implements

---

## Credits

- Fabia Müller, Zurich University of Applied Sciences
- Sebastian Brunner,Zurich University of Applied Sciences
- Llorenç Romá, Cyber-Defence Campus

## Disclaimer

This repository was created as part of a thesis at the [Cyber-Defence Campus](https://www.cydcampus.admin.ch) and is intended solely for academic and security research purposes.

The software provided here is a proof of concept and is not intended for operational or malicious use. The authors assume no responsibility or liability for any misuse, damage, or legal consequences resulting from the use of this code.

By using this software, you agree to do so at your own risk and in compliance with all applicable laws and regulations.

## License

MIT
