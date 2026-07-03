#!/bin/bash
#
# Build the multi-run benchmark firmwares for the nRF52840-DK and collect the
# .hex here (local-tests/bench/). Each firmware repeats a full operation
# BENCH_ITERS times, times it, and prints one incremental-Welford stats line per
# cycle (last line = full result: n / mean / sample-stddev / min / max). See
# bench-stats.h + README.
#
# Matrix: {sw uECC, CC310 hardware} x {CSMA, TSCH}. The label baked into each
# stats line encodes the config, so a pasted "last line" is self-identifying.
#
#   CSMA variants run on the current Firefly gateway (CSMA border router).
#   TSCH variants need the WHOLE path on TSCH: a TSCH Firefly border router
#   (coordinator) + a TSCH-built responder. See README (TSCH bring-up).
#
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"
OBJCOPY="$ARM/arm-none-eabi-objcopy"

# EDHOC bench targets the bridged native responder (fd01::302:304:506:1, node 1).
SERVER_EP='-DEDHOC_CONF_SERVER_EP='"'"'"coap://[fd01::302:304:506:1]"'"'"''

# $1 app-dir, $2 base-name, $3 sw|cc310, $4 csma|tsch
build_one() {
  local app="$1" base="$2" backend="$3" mac="$4"
  local dir="$HERE/$app"
  local extra="" label="$base-$backend-$mac" out="$base-$backend-$mac"
  [ "$backend" = cc310 ] && extra="$extra ECC_HW_BACKEND=cc310"
  [ "$mac" = tsch ] && extra="$extra MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1"
  echo "=== build $app -> $out (label=$label) ==="
  make -C "$dir" TARGET=nrf52840 BOARD=dk clean >/dev/null 2>&1 || true
  env CFLAGS="$SERVER_EP -DBENCH_LABEL='\"$label\"'" \
    make -C "$dir" TARGET=nrf52840 BOARD=dk $extra $TOOLS
  "$OBJCOPY" -O ihex "$dir/build/nrf52840/dk/$app.nrf52840" "$HERE/$out.hex"
  echo "  -> $HERE/$out.hex"
}

# EDHOC c5t handshake benchmark (the template). Extend with more apps as they land.
build_one edhoc-c5t-bench bench-edhoc-c5t sw    csma
build_one edhoc-c5t-bench bench-edhoc-c5t cc310 csma
build_one edhoc-c5t-bench bench-edhoc-c5t sw    tsch
build_one edhoc-c5t-bench bench-edhoc-c5t cc310 tsch

echo ""
echo "=== benchmark firmwares built: ==="
ls -1 "$HERE"/bench-*.hex
