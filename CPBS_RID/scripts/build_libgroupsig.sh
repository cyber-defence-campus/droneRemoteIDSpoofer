#!/usr/bin/env bash
# Build IBM libgroupsig (C) and its Python wrapper (pygroupsig) into third_party/.
#
# libgroupsig is archived and fetches MCL from git HEAD, whose current API
# (no bn_c384_256.h / libmclbn384_256) is incompatible. We pin both:
#   libgroupsig @ LIBGROUPSIG_COMMIT, MCL @ MCL_TAG (the release current at
#   the time of that libgroupsig commit).
#
# Usage: scripts/build_libgroupsig.sh [python-interpreter]
set -euo pipefail

LIBGROUPSIG_COMMIT=7582c6083d10271729bc78c606c238f5025fff12
MCL_TAG=v1.51

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$ROOT/third_party/libgroupsig"
PY="${1:-python3}"
# Absolute path without resolving symlinks (a venv python is a symlink).
case "$PY" in */*) PY="$(cd "$(dirname "$PY")" && pwd)/$(basename "$PY")" ;; esac

if [ ! -d "$SRC/.git" ]; then
    git clone https://github.com/IBM/libgroupsig.git "$SRC"
fi
git -C "$SRC" fetch --depth 1 origin "$LIBGROUPSIG_COMMIT" 2>/dev/null || true
git -C "$SRC" checkout -q "$LIBGROUPSIG_COMMIT"

# Pin MCL (idempotent).
MCL_CMAKE="$SRC/cmake_modules/mcl.cmake"
if ! grep -q "GIT_TAG" "$MCL_CMAKE"; then
    sed -i "s|GIT_REPOSITORY https://github.com/herumi/mcl.git|GIT_REPOSITORY https://github.com/herumi/mcl.git\n  GIT_TAG ${MCL_TAG}|" "$MCL_CMAKE"
fi

# -fcommon: libgroupsig defines `logger`/`sysenv` in headers, which GCC >= 10
# rejects by default (-fno-common).
cmake -S "$SRC" -B "$SRC/build" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_FLAGS=-fcommon
# MCL first: libgroupsig targets don't depend on it, so a parallel build races.
cmake --build "$SRC/build" --target mclproject
cmake --build "$SRC/build" -j"$(nproc)"

# Python wrapper (cffi); paths in libgroupsig_build.py are relative to its dir.
cd "$SRC/src/wrappers/python"
# Drop artefacts from previous builds (they may carry another interpreter's RPATH).
rm -rf build _groupsig*.so _groupsig.c *.egg-info
# path.py >= 16.12 dropped Path.abspath(), which the cffi build script uses.
"$PY" -m pip install cffi "path<16.12"
"$PY" -m pip install --no-build-isolation --no-cache-dir --force-reinstall --no-deps .
