#!/bin/bash
# Build the bulk-send probe for nRF52840-DK, CSMA and TSCH, collect the .hex here.
# SECURITY NOTICE: Test credentials only. Never use in production.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"
OBJCOPY="$ARM/arm-none-eabi-objcopy"

build_one() {
  local mac="$1" extra=""
  [ "$mac" = tsch ] && extra="MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1"
  echo "=== build tsch-bulk-client ($mac) ==="
  rm -rf "$HERE/build"     # full rebuild for the MAC switch, but keep the other MAC's .hex
  make -C "$HERE" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= $extra $TOOLS
  "$OBJCOPY" -O ihex "$HERE/build/nrf/nrf52840/dk/tsch-bulk-client.nrf" \
     "$HERE/bulk-$mac.hex"
  echo "  -> bulk-$mac.hex"
}

build_one csma
build_one tsch
echo "=== bulk probe firmwares: ==="
ls -1 "$HERE"/bulk-*.hex
