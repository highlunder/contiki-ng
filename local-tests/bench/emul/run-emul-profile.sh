#!/bin/bash
#
# Profiling run: build BOTH the emulated nRF EDHOC responder and the c5t sw
# bench client with EDHOC_PROFILE_CYCLES enabled, run a few iterations in the
# cooja-ng emulator, and dump every per-op crypto timing line.
#
# WHY: the emulator does NOT model the DWT cycle counter (CYCCNT reads 0), so
# each PROFILE line's "cycles" is 0 here — but edhoc-profile.h ALSO times each
# op with the rtimer (which cooja-ng models cycle-accurately), reported in us.
# That us figure lets us decompose the emulated handshake into:
#   - the CLIENT's crypto (node 1),
#   - the (emulated-nRF) RESPONDER's crypto (node 2) — which on real hardware
#     runs on a fast native x86 server and is ~free, and is the leading
#     suspect for the emulator being ~1.4x slower than hardware,
#   - the remaining RF/protocol time.
#
# Output lines are prefixed "[Node N/...]" by the test_runner, so client vs
# responder crypto is distinguishable.
#
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
CONTIKI="$HERE/../../.."
COOJA="/home/joel/gemini_workspace/cooja-ng-ge"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm"

SRV_ADDR="fd00::f6ce:3602:e3e9:2"
ITERS="${BENCH_ITERS:-4}"      # few iters: we want per-op crypto lines, not stats
SETTLE="${BENCH_SETTLE_S:-1}"
OUT="$HERE/emul-profile.log"

echo "=== build EDHOC c5t responder (nRF52840, EDHOC_PROFILE on) ==="
make -C "$CONTIKI/tests/21-security-protocols/edhoc-oscore-c5t-server" \
  TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= clean >/dev/null 2>&1 || true
env CFLAGS="-DEDHOC_PROFILE_CYCLES" \
  make -C "$CONTIKI/tests/21-security-protocols/edhoc-oscore-c5t-server" \
  TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= $TOOLS >/dev/null
cp "$CONTIKI/tests/21-security-protocols/edhoc-oscore-c5t-server/build/nrf/nrf52840/dk/edhoc-oscore-c5t-server.nrf" \
   "$HERE/edhoc-c5t-server.nrf52840"

echo "=== build c5t sw bench client (nRF52840, EDHOC_PROFILE on, iters=$ITERS) ==="
make -C "$CONTIKI/local-tests/bench/edhoc-c5t-bench" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= clean >/dev/null 2>&1 || true
env CFLAGS="-DEDHOC_PROFILE_CYCLES -DEDHOC_CONF_SERVER_EP='\"coap://[$SRV_ADDR]\"' -DBENCH_LABEL='\"edhoc-c5t-sw-emul\"' -DBENCH_ITERS=$ITERS -DBENCH_SETTLE_S=$SETTLE" \
  make -C "$CONTIKI/local-tests/bench/edhoc-c5t-bench" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= $TOOLS >/dev/null
cp "$CONTIKI/local-tests/bench/edhoc-c5t-bench/build/nrf/nrf52840/dk/edhoc-c5t-bench.nrf" \
   "$HERE/edhoc-c5t-bench-emul.nrf52840"

echo "=== run in cooja-ng (full output -> $OUT) ==="
"$COOJA/build/test_runner" test "$HERE/emul-edhoc-c5t.json" > "$OUT" 2>&1 || true
echo "=== PROFILE + BENCH lines ==="
grep -E "PROFILE|BENCH edhoc-c5t-sw-emul" "$OUT" || true
