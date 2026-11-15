#!/usr/bin/env bash
#
# Wi-Fi jamming-PoC effectiveness measurement (channel 6). Each run records a few seconds of
# undisturbed delivery (pre-onset baseline, ~100% PDR) then the ~2 s USRP noise burst; the
# analyzer reports the depth of the dip against an assumed 100% baseline. A couple of runs suffice.
#
# Jamming at the receiver is a jammer-vs-signal power contest. At full TX power (20 dBm = 2000 mBm)
# the spoofer out-shouts the maxed-out SDR jammer, so reception barely drops; at minimal TX power
# the co-located RX still gets a clean baseline but the jammer dominates during its burst, so the
# dip is visible. TX_POWER selects the regime (default 0 = minimal, the one that shows the effect):
#   TX_POWER=0     minimal power, jammer wins   (default; the headline result)
#   TX_POWER=2000  full 20 dBm, jammer loses    (the negative control)
# If the baseline comes back lossy (RX can't hear the weak TX), raise TX_POWER (e.g. 300 = 3 dBm).
#
# Needs the USRP B200 + the GNU Radio Wi-Fi jammer (~/gnuradio/wifijam.py), two monitor-mode
# interfaces, and root. The orchestrator calls sudo internally, so run with sudo cached:
#   sudo -v && evaluation/run_jam_wifi.sh
# Override via env vars below.
set -euo pipefail

WIFI_TX="${WIFI_TX:-wlx289401bca9d1}"   # transmits the spoofed drones
WIFI_RX="${WIFI_RX:-wlx00c0ca9910ea}"   # monitor receiver
TX_POWER="${TX_POWER:-0}"               # mBm (100 = 1 dBm); 0 = minimal so the jammer wins
RUNS="${RUNS:-2}"
DURATION="${DURATION:-20}"
DELAY="${DELAY:-5}"
WIFI_DRONES="${WIFI_DRONES:-300}"
PY="${PY:-.venv/bin/python}"
DATA="evaluation/data/jam_eval"
mkdir -p "$DATA"

# Tag outputs by power regime so full-power and min-power runs don't overwrite each other.
if [ "$TX_POWER" -ge 2000 ]; then TAG="fullpow"; else TAG="minpow"; fi

# Put the interfaces into monitor mode (the eval re-asserts monitor/channel/power itself, but this
# gets NetworkManager off them first). Set MONITOR=0 to skip. Tolerant under `set -e`.
ensure_monitor() {
  local iface="$1"
  if iw dev "$iface" info 2>/dev/null | grep -q "type monitor"; then
    echo ">>> $iface already in monitor mode"; return 0
  fi
  echo ">>> setting $iface to monitor mode"
  # Stop NetworkManager re-managing it back to managed mid-capture (the usual cause of 0 reception).
  nmcli dev set "$iface" managed no 2>/dev/null || true
  ip link set "$iface" down 2>/dev/null || true
  iw dev "$iface" set type monitor 2>/dev/null || echo "    [!] could not set $iface to monitor (continuing)"
  ip link set "$iface" up 2>/dev/null || true
}
if [ "${MONITOR:-1}" = "1" ]; then
  ensure_monitor "$WIFI_TX"
  [ "$WIFI_RX" != "$WIFI_TX" ] && ensure_monitor "$WIFI_RX"
fi

for i in $(seq 1 "$RUNS"); do
  echo "### WiFi jammed run $i/$RUNS (${TX_POWER} mBm, $TAG) ###"
  "$PY" evaluation/run_wifi_jam_eval.py --tx-iface "$WIFI_TX" --rx-iface "$WIFI_RX" \
    --channel 6 --tx-power "$TX_POWER" --drones "$WIFI_DRONES" \
    --duration "$DURATION" --delay "$DELAY" --no-plot \
    --out "$DATA/wifi_ch6_jam_${TAG}_run${i}.json"
done

echo; echo "### Wi-Fi effectiveness summary ($TAG, dip vs assumed 100% baseline, onset ~${DELAY}s) ###"
"$PY" evaluation/analyze_jam_effectiveness.py --delay "$DELAY" "$DATA"/wifi_ch6_jam_${TAG}_run*.json
echo; echo ">>> Done. Per-run JSON in $DATA/"
