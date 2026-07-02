#!/bin/bash
#
# Build the Firefly-gateway OTA test ladder for the nRF52840-DK, in both
# release and debug variants, and collect the .hex files here (local-tests/).
#
# Each rung is flashed one at a time (increasing complexity). The boot banner
# on each prints what it is + its target server. See README.md.
#
#   1-net-join    connectivity / RPL join      (no server)
#   2-dtls-psk    DTLS + PSK                    -> setest psk  : [fd00::1]:5686
#   3-dtls-x509   DTLS + X.509                  -> setest A    : [fd00::1]:5684
#   4-dtls-c509   DTLS + C509 (Type-2)          -> setest B2   : [fd00::1]:5687
#
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"
OBJCOPY="$ARM/arm-none-eabi-objcopy"

RUNGS="1-net-join 2-dtls-psk 3-dtls-x509 4-dtls-c509"

build_one() {   # $1 = rung dir, $2 = "" (release) | "1" (debug), $3 = hex suffix
  local rung="$1" dbg="$2" suffix="$3"
  local dir="$HERE/$rung"
  echo "=== build $rung ${suffix:+($suffix)} ==="
  make -C "$dir" TARGET=nrf52840 BOARD=dk clean >/dev/null 2>&1 || true
  make -C "$dir" TARGET=nrf52840 BOARD=dk LOCAL_TEST_DEBUG="$dbg" $TOOLS
  "$OBJCOPY" -O ihex \
    "$dir/build/nrf52840/dk/$rung.nrf52840" \
    "$HERE/$rung$suffix.hex"
  echo "  -> $HERE/$rung$suffix.hex"
}

for rung in $RUNGS; do
  build_one "$rung" ""  ""        # release
  build_one "$rung" "1" "-dbg"    # debug
done

echo ""
echo "=== ladder built. .hex files in $HERE: ==="
ls -1 "$HERE"/*.hex
