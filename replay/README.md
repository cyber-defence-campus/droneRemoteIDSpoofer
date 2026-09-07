# Remote ID PCAP Replay Toolchain

A dedicated toolchain for extracting raw ASTM F3411 Remote ID message payloads from Wi-Fi and Bluetooth PCAP captures and replaying them over the air with accurate inter-packet timing.

## Overview

The replay toolchain consists of two primary scripts:

1. **`pcap_to_replay.py` (Extractor)**: Parses `.pcap` / `.pcapng` packet captures, scans for ASTM F3411 Remote ID payloads across Wi-Fi Beacons, BLE 4 Legacy, BLE 5 Extended, and Wi-Fi NAN, and exports the raw 25-byte message frames into a structured `.jsonl` (JSON Lines) event timeline.
2. **`replay_drones.py` (Replayer)**: Reads the extracted `.jsonl` timeline and transmits the captured Remote ID packets over the air, preserving the original inter-packet timing delays.

---

## Workflow

```
PCAP File (*.pcap)
       │
       ▼
 ┌───────────────────┐
 │ pcap_to_replay.py │ ──> Extracts ASTM payloads & timestamps
 └───────────────────┘
       │
       ▼
Replay Timeline (*.jsonl)
       │
       ▼
 ┌───────────────────┐
 │  replay_drones.py │ ──> Injects over Wi-Fi / BLE / NAN
 └───────────────────┘
```

---

## 1. Extraction: `pcap_to_replay.py`

Scans PCAP files for ASTM F3411 Remote ID signatures (`0xFA0BBC` for Wi-Fi vendor IEs, `0xFFFA` for BLE Service Data, and NAN Action/SDF frames), extracts the 25-byte ASTM message blocks (Basic ID, Location, System, Operator ID), and outputs a line-delimited JSON file (`.jsonl`).

### Usage
```bash
python3 replay/pcap_to_replay.py <input.pcap> <output.jsonl>
```

### JSONL Schema
Each line in the `.jsonl` file represents a captured transmission event:
```json
{
  "time_offset_ms": 1250,
  "transport": "wifi",
  "counter": 4,
  "messages_b64": ["..."],
  "mac": "fe:19:f1:61:3e:61",
  "channel": 6,
  "serial": "Spoofed_Serial_00001"
}
```

---

## 2. Replay: `replay_drones.py`

Replays the captured `.jsonl` timeline over physical wireless interfaces (`wlan1`, `hci0`, or Android NAN bridge).

### Usage
```bash
# Replay using original captured transport mediums
sudo .venv/bin/python3 replay/replay_drones.py replay/captured_flight2.jsonl

# Force cross-transport replay (e.g. replay Wi-Fi capture over BLE 5)
sudo .venv/bin/python3 replay/replay_drones.py replay/captured_flight2.jsonl --transport bt5
```

### Command Line Options

| Argument | Parameter | Default | Description |
|----------|-----------|---------|-------------|
| `jsonl_file` | `path` | *required* | Path to input `.jsonl` replay file |
| `-t`, `--transport` | `wifi\|bt4\|bt5\|nan\|original` | `original` | Target transport medium override |
| `-w`, `--wifi-iface` | `str` | `wlan1` | Wi-Fi interface for injection |
| `-b`, `--ble-adapter` | `str` | `hci0` | BLE HCI adapter name |
| `--nan-port` | `int` | `8080` | TCP port for Android NAN Bridge |
| `--speed` | `float` | `1.0` | Playback speed multiplier (e.g. `2.0` for 2x speed) |

---

## Transport Behavior & Technical Notes

- **Wi-Fi Beacon & BLE 5 Extended**: Replayed as discrete, single-shot frame transmissions matching the captured timeline offsets.
- **BLE 4 Legacy**: Legacy advertisements contain a single 25-byte ASTM message per packet. Replaying in `bt4` mode preserves single-message frame structures.
- **Wi-Fi NAN (Aware)**: Replayed via raw Linux packet injection or the Android `NaN_Bridge` TCP interface.
- **Transport Overriding**: Using `--transport` allows cross-layer playback (e.g., converting a captured Wi-Fi stream into BLE 5 extended advertisements or vice versa).
