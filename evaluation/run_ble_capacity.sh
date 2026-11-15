#!/usr/bin/env bash
#
# Knee-bracketed BLE spoofing-capacity sweep.
#
# Rationale: pdr_tx is 100% everywhere and the only sender-side limit is the per-cycle loop time
# crossing the 1 s RID deadline (the "knee"). Below the knee every run is a flat, lossless straight
# line, so the dense 1..N sweep is wasted airtime. Each sweep here keeps a few geometric anchors in
# the flat region plus +/-2 integer steps bracketing the knee; the existing sender-deadline
# early-termination stops it at the ceiling.
#
# Dual mode transmits a BLE4 legacy stream AND a BLE5 extended stream, but one nRF dongle hears only
# one at a time. We sweep with the BLE5 sniffer, then re-run ONLY the knee points with the BLE4
# sniffer to check whether the legacy stream is starved as the sender saturates (per-stream PDR is
# reported as pdr_rx_stream_percent).
#
# Run under sudo (TX advertising + adapter bring-up need root):
#   sudo evaluation/run_ble_capacity.sh [tx_adapter] [nrf_port] [duration_s]
# e.g.  sudo evaluation/run_ble_capacity.sh hci0 /dev/ttyACM0 10
# Re-run with hci1 to cover the second adapter.
set -euo pipefail

TX="${1:-hci0}"
NRF="${2:-/dev/ttyACM0}"
DUR="${3:-10}"
PY="${PY:-.venv/bin/python}"
DATA="evaluation/data/capacity_ble_${TX}"
mkdir -p "$DATA"

cap() {
  # Resume support: skip a config whose output JSON already exists and is non-empty, unless FORCE=1.
  local out="" prev=""
  for a in "$@"; do [ "$prev" = "--out" ] && out="$a"; prev="$a"; done
  if [ -n "$out" ] && [ -s "$out" ] && [ -z "${FORCE:-}" ]; then
    echo ">>> skip (already done): $out"; return 0
  fi
  echo; echo ">>> $*"; "$PY" evaluation/ble_capacity.py --tx-adapter "$TX" --nrf-port "$NRF" --duration "$DUR" "$@"
}

# --- Pure BT5 extended (Coded PHY), BLE5 sniffer ---
cap --ble-mode extended --ble-interval-ms 20  --rx-mode ble5 --drones 1,2,4,8,16,33,34,35,36,37 --out "$DATA/extended_20ms.json"
cap --ble-mode extended --ble-interval-ms 30  --rx-mode ble5 --drones 1,2,4,8,16,26,27,28,29,30 --out "$DATA/extended_30ms.json"
cap --ble-mode extended --ble-interval-ms 50  --rx-mode ble5 --drones 1,2,4,8,16,17,18,19,20    --out "$DATA/extended_50ms.json"
cap --ble-mode extended --ble-interval-ms 75  --rx-mode ble5 --drones 1,2,4,8,11,12,13,14,15    --out "$DATA/extended_75ms.json"
cap --ble-mode extended --ble-interval-ms 100 --rx-mode ble5 --drones 1,2,4,8,9,10,11,12         --out "$DATA/extended_100ms.json"
cap --ble-mode extended --ble-interval-ms 150 --rx-mode ble5 --drones 1,2,5,6,7,8,9              --out "$DATA/extended_150ms.json"
cap --ble-mode extended --ble-interval-ms 200 --rx-mode ble5 --drones 1,3,4,5,6,7                --out "$DATA/extended_200ms.json"

# --- Extended advertising w/ legacy AD (BLE4 1M), BLE4 sniffer ---
cap --ble-mode ext-legacy --ble-interval-ms 20  --rx-mode ble4 --drones 1,2,4,8,17,18,19,20,21 --out "$DATA/ext-legacy_20ms.json"
cap --ble-mode ext-legacy --ble-interval-ms 30  --rx-mode ble4 --drones 1,2,4,8,11,12,13,14,15 --out "$DATA/ext-legacy_30ms.json"
cap --ble-mode ext-legacy --ble-interval-ms 50  --rx-mode ble4 --drones 1,2,4,7,8,9,10,11       --out "$DATA/ext-legacy_50ms.json"
cap --ble-mode ext-legacy --ble-interval-ms 75  --rx-mode ble4 --drones 1,2,4,5,6,7,8           --out "$DATA/ext-legacy_75ms.json"
cap --ble-mode ext-legacy --ble-interval-ms 100 --rx-mode ble4 --drones 1,3,4,5,6,7             --out "$DATA/ext-legacy_100ms.json"
cap --ble-mode ext-legacy --ble-interval-ms 150 --rx-mode ble4 --drones 1,2,3,4,5               --out "$DATA/ext-legacy_150ms.json"
cap --ble-mode ext-legacy --ble-interval-ms 200 --rx-mode ble4 --drones 1,2,3,4,5               --out "$DATA/ext-legacy_200ms.json"

# --- Pure legacy (BT4), BLE4 sniffer ---
cap --ble-mode legacy --ble-interval-ms 100 --rx-mode ble4 --drones 2,3,4,5,6 --out "$DATA/legacy_100ms.json"
cap --ble-mode legacy --ble-interval-ms 150 --rx-mode ble4 --drones 1,2,3,4,5 --out "$DATA/legacy_150ms.json"
cap --ble-mode legacy --ble-interval-ms 200 --rx-mode ble4 --drones 1,2,3,4,5 --out "$DATA/legacy_200ms.json"

# --- Dual (ext fixed 20ms, vary legacy interval): full BLE5 sweep, then BLE4 knee-only ---
# interval : full-sweep drones                 : knee-only drones (BLE4 starvation check)
dual_full=( "20:1,2,4,8,17,18,19,20,21" "30:1,2,4,8,11,12,13,14,15" "50:1,2,4,6,7,8,9,10" \
            "75:1,2,4,5,6,7,8" "100:1,3,4,5,6,7" "150:1,2,3,4,5" "200:1,2,3,4,5" )
dual_knee=( "20:17,18,19,20,21" "30:11,12,13,14,15" "50:6,7,8,9,10" \
            "75:4,5,6,7,8" "100:3,4,5,6,7" "150:1,2,3,4,5" "200:1,2,3,4,5" )
for e in "${dual_full[@]}"; do iv="${e%%:*}"; dr="${e#*:}"
  cap --ble-mode dual --extended-interval-ms 20 --legacy-interval-ms "$iv" --rx-mode ble5 --drones "$dr" --out "$DATA/dual_leg${iv}ms_ble5.json"
done
for e in "${dual_knee[@]}"; do iv="${e%%:*}"; dr="${e#*:}"
  cap --ble-mode dual --extended-interval-ms 20 --legacy-interval-ms "$iv" --rx-mode ble4 --drones "$dr" --out "$DATA/dual_leg${iv}ms_ble4_knee.json"
done

echo; echo ">>> Done. Results in $DATA/"
