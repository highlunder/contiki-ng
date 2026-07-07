#!/bin/bash
# Diagnostic build of rxdiag root+leaf for cc2538dk (cooja-ng emulator) with
# TSCH (MAC) + RPL info logging, to observe leaf TSCH association + RPL join.
# SECURITY NOTICE: Test credentials only. Never use in production.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="/home/joel/toolchains/arm-gcc/bin"
make -C "$HERE" TARGET=cc2538dk MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 \
  DEFINES=LOG_CONF_LEVEL_MAC=LOG_LEVEL_DBG,LOG_CONF_LEVEL_RPL=LOG_LEVEL_INFO \
  CC="$ARM/arm-none-eabi-gcc" AS="$ARM/arm-none-eabi-gcc" LD="$ARM/arm-none-eabi-gcc" \
  AR="$ARM/arm-none-eabi-ar" OBJCOPY="$ARM/arm-none-eabi-objcopy" \
  NM="$ARM/arm-none-eabi-nm" SIZE="$ARM/arm-none-eabi-size"
echo "=== built cc2538dk diag firmwares ==="
ls -1 "$HERE"/build/cc2538dk/rxdiag-root.cc2538dk "$HERE"/build/cc2538dk/rxdiag-leaf.cc2538dk
