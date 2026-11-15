#!/usr/bin/env bash
# Build the C benchmark and the ODID reference checker.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LG="$ROOT/third_party/libgroupsig"
ODID="$ROOT/../opendroneid-core-c/libopendroneid"

gcc -O2 -fcommon -I"$LG/src/include" -I"$LG/src" -I"$LG/build/external/include" \
    -o "$ROOT/bench/bench_groupsig" "$ROOT/bench/bench_groupsig.c" \
    -L"$LG/build/lib" -L"$LG/build/external/lib" -Wl,-rpath,"$LG/build/lib:$LG/build/external/lib" \
    -lgroupsig -lmclbn384_256 -lmcl -lssl -lcrypto -lstdc++ -lm

if [ -d "$ODID" ]; then
    gcc -O2 -I"$ODID" -o "$ROOT/bench/odid_refcheck" "$ROOT/bench/odid_refcheck.c" "$ODID/opendroneid.c" -lm
fi

gcc -O2 -fcommon -I"$LG/src/include" -I"$LG/src" -I"$LG/build/external/include" \
    -o "$ROOT/bench/bench_open_scale" "$ROOT/bench/bench_open_scale.c" \
    -L"$LG/build/lib" -L"$LG/build/external/lib" -Wl,-rpath,"$LG/build/lib:$LG/build/external/lib" \
    -lgroupsig -lmclbn384_256 -lmcl -lssl -lcrypto -lstdc++ -lm
