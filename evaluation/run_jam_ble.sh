#!/usr/bin/env bash
#
# BLE jamming-PoC effectiveness measurement (primary advertising channel 37). Each run records a
# few seconds of undisturbed delivery (pre-onset baseline) then the ~2 s USRP noise burst; the
# analyzer reports the depth of the dip against an assumed 100% baseline. A couple of runs suffice.
#
# BLE is advertised ext-legacy and the nRF sniffer is restricted to ch 37 (where the jammer sits).
#
# Needs the USRP B200 + the GNU Radio BLE jammer (~/blejam.py), the nRF sniffer dongle, and root.
# The orchestrator calls sudo internally, so run with sudo cached:
#   sudo -v && evaluation/run_jam_ble.sh
# Override via env vars below.
set -euo pipefail

TX_ADAPTER="${TX_ADAPTER:-hci0}"
NRF_PORT="${NRF_PORT:-/dev/ttyACM0}"
RUNS="${RUNS:-2}"
DURATION="${DURATION:-20}"
DELAY="${DELAY:-5}"
BLE_DRONES="${BLE_DRONES:-5}"
PY="${PY:-.venv/bin/python}"
DATA="evaluation/data/jam_eval"
mkdir -p "$DATA"

for i in $(seq 1 "$RUNS"); do
  echo "### BLE jammed run $i/$RUNS ###"
  "$PY" evaluation/run_ble_jam_eval.py --tx-adapter "$TX_ADAPTER" --nrf-port "$NRF_PORT" \
    --ble-mode ext-legacy --rx-mode ble4 --filter-channel 37 \
    --drones "$BLE_DRONES" --duration "$DURATION" --delay "$DELAY" --no-plot \
    --out "$DATA/ble_ch37_jam_run${i}.json"
done

echo; echo "### BLE effectiveness summary (dip vs assumed 100% baseline, onset ~${DELAY}s) ###"
"$PY" evaluation/analyze_jam_effectiveness.py --delay "$DELAY" "$DATA"/ble_ch37_jam_run*.json
echo; echo ">>> Done. Per-run JSON in $DATA/"
