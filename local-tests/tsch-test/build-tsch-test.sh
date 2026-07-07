#!/bin/bash
#
# Build a minimal TSCH network test (real hardware):
#   - Firefly (zoul) rpl-border-router built for TSCH  -> TSCH coordinator + RPL
#     root + 6LoWPAN gateway (becomes coordinator automatically once it is RPL
#     root, via tsch_rpl_callback_new_dio_interval -> tsch_set_coordinator(1)).
#   - nRF52840-DK 1-net-join built for TSCH            -> joins the TSCH network.
#
# Both built with MAKE_MAC=MAKE_MAC_TSCH + MAKE_WITH_ORCHESTRA=1. Artifacts:
#   border-router-tsch.bin   (flash to the Firefly via cc2538-bsl)
#   1-net-join-tsch.hex      (flash to the DK via nrfjprog)
#
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
CONTIKI="$HERE/../.."
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"
OBJCOPY="$ARM/arm-none-eabi-objcopy"
TSCH="MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1"

echo "=== Firefly TSCH border-router (coordinator) ==="
make -C "$CONTIKI/examples/rpl-border-router" TARGET=zoul BOARD=firefly clean >/dev/null 2>&1 || true
make -C "$CONTIKI/examples/rpl-border-router" TARGET=zoul BOARD=firefly $TSCH $TOOLS
"$OBJCOPY" -O binary \
  "$CONTIKI/examples/rpl-border-router/build/zoul/firefly/border-router.zoul" \
  "$HERE/border-router-tsch.bin"
echo "  -> $HERE/border-router-tsch.bin"

echo "=== nRF52840-DK TSCH node (1-net-join) ==="
make -C "$CONTIKI/local-tests/1-net-join" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= clean >/dev/null 2>&1 || true
make -C "$CONTIKI/local-tests/1-net-join" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= $TSCH $TOOLS
"$OBJCOPY" -O ihex \
  "$CONTIKI/local-tests/1-net-join/build/nrf/nrf52840/dk/1-net-join.nrf" \
  "$HERE/1-net-join-tsch.hex"
echo "  -> $HERE/1-net-join-tsch.hex"

echo ""
echo "Done. Flash border-router-tsch.bin to the Firefly and 1-net-join-tsch.hex to the DK."
