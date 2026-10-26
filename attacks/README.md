# Remote ID Security Attacks & Exploit Verification Suite

This directory contains offensive security tools, over-the-air (OTA) exploit proofs-of-concept, session hijacking harnesses, and protocol weakness solvers evaluated in this framework.

---

## Directory Overview

```
attacks/
├── takeover/                  # Real-time drone session hijacking & trajectory hiding
│   ├── takeover_figure8.py    # Sniffs target drone and injects a figure-8 trajectory deviation
│   ├── takeover_predictive.py # Sniffs target drone and projects predictive kinematic extrapolation
│   ├── cts_inject.c           # Layer 2 Wi-Fi CTS-to-Self frame injector (RF channel silencing)
│   └── Makefile               # Build script for cts_inject (requires libpcap)
│
├── protocol/                  # Protocol & standard specification weakness solvers
│   └── easa_operator_id_bruteforce.py # EASA EN 4709-002 Luhn mod-36 secret key collision solver
│
├── ephemeral_swarm.py         # Multi-transport identity-rotation tracking saturation (DDoS)
└── fuzz_rid.py                # ASTM F3411 Remote ID over-the-air mutation fuzzer
```

---

## 1. Drone Session Takeover & RF Suppression (`attacks/takeover/`)

### A. Figure-8 Trajectory Hijacking
Sniffs for a legitimate drone's ASTM Remote ID broadcasts, captures its identity (Serial, MAC, Base Location), locks onto the session, and begins broadcasting a figure-8 trajectory deviation.

```bash
# BLE 5 Extended Advertising Takeover
sudo .venv/bin/python attacks/takeover/takeover_figure8.py \
  --transport ble --ble-adapter hci0 --interval 100

# Wi-Fi Beacon Takeover
sudo .venv/bin/python attacks/takeover/takeover_figure8.py \
  --transport wifi --interface wlan1
```

### B. Predictive Trajectory Hiding
Sniffs a drone's active flight vector and extrapolates its future path using linear kinematics, masking the drone's actual current location.

```bash
sudo .venv/bin/python attacks/takeover/takeover_predictive.py \
  --transport wifi --interface wlan1
```

### C. Layer 2 Wi-Fi Channel Silencing (`cts_inject`)
Injects continuous IEEE 802.11 Clear-to-Send (CTS-to-Self) frames with maximum 32,767 µs Network Allocation Vector (NAV) durations to silence the genuine drone's transmissions and prevent RF packet collisions during takeover.

```bash
# Build binary
cd attacks/takeover && make

# Inject CTS silencing on monitor interface:
sudo ./attacks/takeover/cts_inject wlan1mon
```

---

## 2. Protocol Specification Weaknesses (`attacks/protocol/`)

### EASA Operator ID Checksum Collision (`easa_operator_id_bruteforce.py`)
Demonstrates that the EU EN 4709-002 Luhn mod-36 checksum standard for Remote ID Operator IDs (Type 5) is fundamentally weak: for any intercepted 16-character public Operator ID, an attacker can compute all 1,296 valid 3-character secret keys in $<0.15$ seconds to forge authentic-looking registration credentials.

```bash
.venv/bin/python attacks/protocol/easa_operator_id_bruteforce.py
```

---

## 3. Swarm Saturation & Protocol Fuzzing

### A. Ephemeral Swarm Identity Flooding (`ephemeral_swarm.py`)
Floods receiver tracking tables by rapidly transmitting 1–3 beacons per drone and immediately rotating MAC addresses, serial numbers, and coordinates across Wi-Fi, BLE, and NAN.

```bash
sudo .venv/bin/python attacks/ephemeral_swarm.py \
  -t all -i wlan1 --ble-adapter hci0 -b 100 -d 2.0
```

### B. Remote ID Protocol Mutation Fuzzing (`fuzz_rid.py`)
Mutates ASTM F3411 headers, message pack counts, authentication page headers, string terminators, and coordinate projections to test receiver parser resilience against memory corruption and projection crashes.

```bash
sudo .venv/bin/python attacks/fuzz_rid.py \
  -t wifi -i wlan1 -f all -c 3.0
```
