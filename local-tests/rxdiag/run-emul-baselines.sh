#!/bin/bash
# Reproduce the rxdiag emulator baselines (the reference the HW ladder is compared
# against). Each emul JSON needs its matching MAC build first: build/nrf/nrf52840/dk is
# MAC-specific, so we rebuild the nRF pair per MAC before running its config.
# SECURITY NOTICE: Test credentials only. Never use in production.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="/home/joel/toolchains/arm-gcc/bin"
TR="/home/joel/gemini_workspace/cooja-ng-ge/build/test_runner"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"

build_nrf() {   # $1 = tsch|csma
  local extra=""
  [ "$1" = tsch ] && extra="MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1"
  rm -rf "$HERE/build/nrf"
  make -C "$HERE" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= $extra $TOOLS >/dev/null
}

echo "=== nRF-nRF TSCH baseline ==="
build_nrf tsch
"$TR" test "$HERE/emul-rxdiag-tsch.json" | tail -6

echo "=== nRF-nRF CSMA baseline (rung R4) ==="
build_nrf csma
"$TR" test "$HERE/emul-rxdiag-nrf-csma.json" | tail -6

echo "NOTE: mixed CC2538<->nRF TSCH (emul-rxdiag-{firefly,cc2538}-nrf-tsch.json) does NOT"
echo "      converge in cooja-ng -- see RXDIAG-EMULATOR-BASELINE.md. The all-nRF runs above"
echo "      are the faithful leaf reference (leaf = identical nRF firmware on HW and emulator)."
