#!/usr/bin/env bash
#
# Wi-Fi (ASTM F3411) beacon spoofing-capacity KNEE sweep.
#
# Goal: find, on the *current* tool and a single chosen adapter, the largest
# phantom-drone roster that still holds the mandated broadcast cadence --- i.e.
# the point where the sender starts missing its per-cycle deadline. It sweeps
# far past the knee and lets wifi_capacity.py's --consecutive-misses
# early-stop halt each cell once deadlines are *consistently* missed (100% of
# cycles missed for N runs in a row). The knee (first/last clean roster) is read
# back from the per-run missed-deadline counts; the per-cycle loop_stats also fit
# the per-beacon service time t_beacon, giving N* = cadence / t_beacon.
#
# Two mandated cadences are swept:
#   1 Hz    (social channels, --interval 1.0)      -- RID minimum broadcast rate
#   200 TU  (non-social channels, --interval 0.2048 ~ 4.88 Hz)
#
# Rate comparison (1 Mbps DSSS vs 6 Mbps OFDM) is run on 2.4 GHz only: the harness
# bumps 1 Mbps to 6 Mbps OFDM on 5 GHz, so a 5 GHz "1 Mbps" cell is not distinct.
# 5 GHz runs at 6 Mbps and carries the high-capacity headline.
#
# Needs root (monitor-mode AF_PACKET TX/RX + `iw set channel`). Run under sudo:
#   sudo evaluation/run_wifi_capacity.sh <tx_iface> <rx_iface>
# e.g.  sudo evaluation/run_wifi_capacity.sh wlan1 wlx00c0cabb1654
#
# Tunables (env):
#   DUR_1HZ   per-point duration for 1 Hz cells   (default 30 s -> 30 cycles, so the
#             missed-deadline fraction near the knee is well resolved)
#   DUR_5HZ   per-point duration for 200 TU cells (default 10 s -> ~49 cycles)
#   DRONES_1HZ  roster sweep for 1 Hz cells   (default 200-3600:100)
#   DRONES_5HZ  roster sweep for 200 TU cells (default 50-1600:50)
#   MISSES    consecutive full-miss runs before early-stop (default 2)
#   BANDS     which bands to run: "24", "5", or "24 5" (default "24 5")
#   MONITOR   1 = put ifaces into monitor mode here (default); 0 = assume preconfigured
#   FORCE     1 = re-run cells whose output JSON already exists (default: skip/resume)
#   PCAP      1 = capture the RX monitor iface to a per-cell .pcap for the whole run
#             (default; records the real on-air PHY rate, retries, timing, RID IEs so
#             the actual data rate can be verified post-hoc -- commodity monitor-mode
#             injection often ignores the requested radiotap rate). 0 = disable.
#   PCAP_SNAPLEN  bytes captured per frame (default 0 = full frame; set e.g. 256 to
#             keep only radiotap + headers + RID IE and shrink the files).
set -euo pipefail

TX="${1:?tx monitor iface, e.g. wlan1}"
RX="${2:?rx monitor iface, e.g. wlx00c0cabb1654}"
PY="${PY:-.venv/bin/python}"

DUR_1HZ="${DUR_1HZ:-30}"
DUR_5HZ="${DUR_5HZ:-10}"
DRONES_1HZ="${DRONES_1HZ:-200-3600:100}"
DRONES_5HZ="${DRONES_5HZ:-50-1600:50}"
MISSES="${MISSES:-2}"
BANDS="${BANDS:-24 5}"
PCAP="${PCAP:-1}"
PCAP_SNAPLEN="${PCAP_SNAPLEN:-0}"

DATA="evaluation/data/capacity_wifi_${TX}"
mkdir -p "$DATA"

# Pick a capture tool once (dumpcap handles radiotap/monitor cleanly; tcpdump is the
# fallback). Empty => no capture available, so PCAP is forced off with a warning.
CAP_TOOL=""
if [ "$PCAP" = "1" ]; then
  if command -v dumpcap >/dev/null 2>&1; then CAP_TOOL="dumpcap"
  elif command -v tcpdump >/dev/null 2>&1; then CAP_TOOL="tcpdump"
  else echo ">>> [!] neither dumpcap nor tcpdump found; disabling PCAP capture"; PCAP=0
  fi
fi

# Kill any stray capture if the script is interrupted mid-cell.
CAP_PID=""
stop_capture() {
  [ -n "$CAP_PID" ] || return 0
  kill -INT "$CAP_PID" 2>/dev/null || true
  wait "$CAP_PID" 2>/dev/null || true
  CAP_PID=""
}
trap 'stop_capture' EXIT INT TERM

ensure_monitor() {
  local iface="$1"
  if iw dev "$iface" info 2>/dev/null | grep -q "type monitor"; then
    echo ">>> $iface already in monitor mode"; return 0
  fi
  echo ">>> setting $iface to monitor mode"
  # Tolerant under `set -e`: a busy/5 GHz-incapable adapter must not abort the sweep.
  # Stop NetworkManager re-managing it mid-capture (the usual cause of 0 reception).
  nmcli dev set "$iface" managed no 2>/dev/null || true
  ip link set "$iface" down 2>/dev/null || true
  iw dev "$iface" set type monitor 2>/dev/null || echo "    [!] could not set $iface to monitor (continuing)"
  ip link set "$iface" up 2>/dev/null || true
}
if [ "${MONITOR:-1}" = "1" ]; then
  ensure_monitor "$TX"
  [ "$RX" != "$TX" ] && ensure_monitor "$RX"
fi

# cap <channel> <rate> <interval_s> <drones_spec> <duration_s> <out>
cap() {
  local ch="$1" rate="$2" interval="$3" drones="$4" dur="$5" out="$6"
  if [ -s "$out" ] && [ -z "${FORCE:-}" ]; then
    echo ">>> skip (already done, set FORCE=1 to redo): $out"; return 0
  fi
  echo; echo ">>> ch$ch ${rate}Mbps interval=${interval}s dur=${dur}s drones=${drones} -> $out"

  # Start a full-cell capture on the RX monitor iface (independent AF_PACKET socket,
  # so it coexists with the harness' own sniffer). Captures radiotap -> real PHY rate.
  local pcap="${out%.json}.pcap"
  if [ "$PCAP" = "1" ] && [ -n "$CAP_TOOL" ]; then
    case "$CAP_TOOL" in
      dumpcap) dumpcap -i "$RX" -s "$PCAP_SNAPLEN" -w "$pcap" >/dev/null 2>&1 & ;;
      tcpdump) tcpdump -i "$RX" -s "$PCAP_SNAPLEN" -w "$pcap" >/dev/null 2>&1 & ;;
    esac
    CAP_PID="$!"
    sleep 0.3  # let the capture socket bind before TX starts
    echo "    capturing -> $pcap (pid $CAP_PID)"
  fi

  if ! "$PY" evaluation/wifi_capacity.py --tx-iface "$TX" --rx-iface "$RX" \
         --channel "$ch" --rate "$rate" --interval "$interval" --duration "$dur" \
         --drones "$drones" --consecutive-misses "$MISSES" --out "$out"; then
    echo "    [!] cell failed (continuing with next)"
  fi

  stop_capture
  [ "$PCAP" = "1" ] && [ -s "$pcap" ] && echo "    pcap: $(du -h "$pcap" | cut -f1)"
}

run_24ghz() {
  echo; echo "========== 2.4 GHz: 1 Mbps vs 6 Mbps comparison =========="
  # 1 Hz (social ch 6)
  cap 6 1 1.0    "$DRONES_1HZ" "$DUR_1HZ" "$DATA/ch6_1hz_1mbps.json"
  cap 6 6 1.0    "$DRONES_1HZ" "$DUR_1HZ" "$DATA/ch6_1hz_6mbps.json"
  # 200 TU (non-social ch 1)
  cap 1 1 0.2048 "$DRONES_5HZ" "$DUR_5HZ" "$DATA/ch1_200tu_1mbps.json"
  cap 1 6 0.2048 "$DRONES_5HZ" "$DUR_5HZ" "$DATA/ch1_200tu_6mbps.json"
}

run_5ghz() {
  echo; echo "========== 5 GHz: 6 Mbps headline =========="
  cap 149 6 1.0    "$DRONES_1HZ" "$DUR_1HZ" "$DATA/ch149_1hz_6mbps.json"
  cap 157 6 0.2048 "$DRONES_5HZ" "$DUR_5HZ" "$DATA/ch157_200tu_6mbps.json"
}

for b in $BANDS; do
  case "$b" in
    24) run_24ghz ;;
    5)  run_5ghz ;;
    *)  echo "    [!] unknown band '$b' (use 24 and/or 5)";;
  esac
done

echo; echo ">>> Done. Results in $DATA/"
echo ">>> Re-run analysis: point the capacity analyzer at $DATA/ to read the"
echo "    per-cadence knees (last zero-miss roster) and the t_beacon fit."
