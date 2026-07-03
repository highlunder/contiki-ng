#!/bin/bash
#
# Run a bench firmware in the cooja-ng emulator (emulated nRF52840-DK) so the
# SAME firmware can be compared hardware-vs-simulation, and then scaled to node
# counts hardware can't reach. Builds the c5t sw bench client + the nRF EDHOC
# responder, then runs the 2-node config in cooja-ng.
#
# KEY GOTCHA: an emulated nRF node's IPv6 address is FICR-derived, NOT the
# native-cooja "…202:2:2:2" pattern, and NOT the [PKT] radio-trace rendering
# (which is a broken artifact). It is deterministic per node id. For the server
# at node id 2 it is fd00::f6ce:3602:e3e9:2 (link-local fe80::f6ce:3602:e3e9:2,
# from the firmware's own "Tentative link-local" log). The client's
# EDHOC_CONF_SERVER_EP must be built to point there.
#
# Requires the ARM toolchain + a built cooja-ng test_runner (cooja-ng-ge).
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
CONTIKI="$HERE/../../.."
COOJA="/home/joel/gemini_workspace/cooja-ng-ge"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm"

# Server = node id 2 -> deterministic FICR-derived address.
SRV_ADDR="fd00::f6ce:3602:e3e9:2"
ITERS="${BENCH_ITERS:-30}"     # sim is slower per iter (crypto emulation); 30 is a good default
SETTLE="${BENCH_SETTLE_S:-1}"  # UDGM lossless -> no RPL healing needed, short settle

echo "=== build EDHOC c5t responder (nRF52840) ==="
make -C "$CONTIKI/tests/21-security-protocols/edhoc-oscore-c5t-server" \
  TARGET=nrf52840 BOARD=dk $TOOLS >/dev/null
cp "$CONTIKI/tests/21-security-protocols/edhoc-oscore-c5t-server/build/nrf52840/dk/edhoc-oscore-c5t-server.nrf52840" \
   "$HERE/edhoc-c5t-server.nrf52840"

echo "=== build c5t sw bench client (nRF52840, server=$SRV_ADDR, iters=$ITERS) ==="
make -C "$CONTIKI/local-tests/bench/edhoc-c5t-bench" TARGET=nrf52840 BOARD=dk clean >/dev/null 2>&1 || true
env CFLAGS="-DEDHOC_CONF_SERVER_EP='\"coap://[$SRV_ADDR]\"' -DBENCH_LABEL='\"edhoc-c5t-sw-emul\"' -DBENCH_ITERS=$ITERS -DBENCH_SETTLE_S=$SETTLE" \
  make -C "$CONTIKI/local-tests/bench/edhoc-c5t-bench" TARGET=nrf52840 BOARD=dk $TOOLS >/dev/null
cp "$CONTIKI/local-tests/bench/edhoc-c5t-bench/build/nrf52840/dk/edhoc-c5t-bench.nrf52840" \
   "$HERE/edhoc-c5t-bench-emul.nrf52840"

echo "=== run in cooja-ng ==="
"$COOJA/build/test_runner" test "$HERE/emul-edhoc-c5t.json" | \
  grep -E "BENCH edhoc-c5t-sw-emul|TEST PASSED|TEST FAILED|Speed ratio"
