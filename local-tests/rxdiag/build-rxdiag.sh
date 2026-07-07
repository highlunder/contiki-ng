#!/bin/bash
# Build the rxdiag TSCH receive-path bisection harness (root + leaf) for the
# nRF52840-DK, CSMA and TSCH, collecting .hex files here.
# SECURITY NOTICE: Test credentials only. Never use in production.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"
OBJCOPY="$ARM/arm-none-eabi-objcopy"
B="$HERE/build/nrf52840/dk"

build_one() {
  local mac="$1" extra=""
  [ "$mac" = tsch ] && extra="MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1"
  echo "=== build rxdiag root+leaf ($mac) ==="
  rm -rf "$HERE/build"
  make -C "$HERE" TARGET=nrf52840 BOARD=dk $extra $TOOLS
  "$OBJCOPY" -O ihex "$B/rxdiag-root.nrf52840" "$HERE/rxdiag-root-$mac.hex"
  "$OBJCOPY" -O ihex "$B/rxdiag-leaf.nrf52840" "$HERE/rxdiag-leaf-$mac.hex"
  echo "  -> rxdiag-root-$mac.hex  rxdiag-leaf-$mac.hex"
}

# Firefly (Zolertia, cc2538) = the practical real-RF PARTNER node: it is the
# proven RPL-root/TSCH-coordinator the nRF-DK joins OTA (project_firefly_gateway).
# Build ONLY the root there (tiny app, fits cc2538 32KB); the nRF-DK is the leaf.
build_firefly() {
  local mac="$1" extra=""
  [ "$mac" = tsch ] && extra="MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1"
  echo "=== build rxdiag root (firefly/$mac) ==="
  rm -rf "$HERE/build"
  make -C "$HERE" rxdiag-root TARGET=zoul BOARD=firefly $extra $TOOLS
  "$OBJCOPY" -O binary "$HERE/build/zoul/firefly/rxdiag-root.zoul" \
     "$HERE/rxdiag-root-firefly-$mac.bin"
  echo "  -> rxdiag-root-firefly-$mac.bin"
}

build_one tsch      # nRF root+leaf (2-nRF HW or cooja-ng emulator)
build_one csma
build_firefly tsch  # Firefly root = real-RF partner for the nRF-DK leaf
build_firefly csma
echo "=== rxdiag firmwares: ==="
ls -1 "$HERE"/rxdiag-*.hex "$HERE"/rxdiag-*.bin
