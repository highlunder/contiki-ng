#!/bin/bash
# Stage the H6 (real-RF multi-hop) firmware set, one image per (app, board,
# TOPO_ROLE). See PLAN-c509-lice-followup.md §10.6 and TOPO-FILTER-README.md.
#
# CRITICAL: TOPO_ROLE is injected via the CFLAGS env var, and a plain rebuild
# does NOT pick up an env-CFLAGS change (make reports "Nothing to be done").
# This script therefore `make clean`s before every per-role build -- otherwise a
# stale image without the topology filter ships and all nodes hear each other
# (no multi-hop). Each image is objcopy'd to a role-tagged .hex in fw-hw/ right
# after its build, before the next role overwrites the build tree.
#
# Boards: DK = nrf52840/dk (root + leaf/DUT, flashed via nrfjprog/J-Link),
#         dongle = nrf52840/dongle (relays, flashed via nrfutil DFU).
# MAC = TSCH (multi-hop). Override the toolchain dir with ARM=... if needed.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
CONTIKI=$(cd "$HERE/../.." && pwd)
ARM=${ARM:-/home/joel/toolchains/arm-gcc/bin}
OUT="$HERE/fw-hw"
FW_ID=${FW_ID:-$(date -u +%Y%m%d)}
mkdir -p "$OUT"

TC="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"

# build_one <appdir> <appname> <board> <role> <outname>
build_one() {
  local appdir="$1" appname="$2" board="$3" role="$4" outname="$5"
  echo "=== $outname  (role $role, $board) ==="
  make -C "$CONTIKI/$appdir" TARGET=nrf BOARD="$board" clean >/dev/null 2>&1 || true
  env CFLAGS="-DTOPO_ROLE=$role" make -C "$CONTIKI/$appdir" \
      TARGET=nrf BOARD="$board" MAKE_MAC=MAKE_MAC_TSCH LDFLAGS_WERROR= \
      FW_ID="$FW_ID" $TC >/dev/null
  "$ARM/arm-none-eabi-objcopy" -O ihex \
      "$CONTIKI/$appdir/build/nrf/$board/$appname.nrf" "$OUT/$outname.hex"
  echo "    -> $OUT/$outname.hex"
}

# --- H6a: EDHOC c5t (instrumented bench) vs x5c, 1->3 hops ------------------
# Roots (DK, role 1):
build_one tests/21-security-protocols/edhoc-oscore-c5t-server  edhoc-oscore-c5t-server  nrf52840/dk 1 c5t-server-r1-dk
build_one tests/21-security-protocols/edhoc-oscore-x509-server edhoc-oscore-x509-server nrf52840/dk 1 x5c-server-r1-dk
# Relays (dongle, roles 2 and 3):
build_one local-tests/multihop/relay relay nrf52840/dongle 2 relay-r2-dongle
build_one local-tests/multihop/relay relay nrf52840/dongle 3 relay-r3-dongle
# Leaf/DUT (DK): c5t bench + x5c client at roles 2/3/4 (= 1/2/3 hops from root):
build_one local-tests/bench/edhoc-c5t-bench            edhoc-c5t-bench          nrf52840/dk 2 c5t-leaf-r2-dk
build_one local-tests/bench/edhoc-c5t-bench            edhoc-c5t-bench          nrf52840/dk 3 c5t-leaf-r3-dk
build_one local-tests/bench/edhoc-c5t-bench            edhoc-c5t-bench          nrf52840/dk 4 c5t-leaf-r4-dk
build_one tests/21-security-protocols/edhoc-oscore-x509-client edhoc-oscore-x509-client nrf52840/dk 2 x5c-leaf-r2-dk
build_one tests/21-security-protocols/edhoc-oscore-x509-client edhoc-oscore-x509-client nrf52840/dk 3 x5c-leaf-r3-dk
build_one tests/21-security-protocols/edhoc-oscore-x509-client edhoc-oscore-x509-client nrf52840/dk 4 x5c-leaf-r4-dk

echo "=== staged $(ls -1 "$OUT"/*.hex 2>/dev/null | wc -l) firmwares in $OUT ==="
