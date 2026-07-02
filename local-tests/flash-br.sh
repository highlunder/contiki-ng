#!/bin/bash
#
# Flash the Zolertia Firefly RPL-root / 6LoWPAN border-router over the CC2538
# ROM BSL (pure Python cc2538-bsl.py — no ARM toolchain needed on this host).
#
# Run on the WSL host with the Firefly's CP2104 attached (usbipd), NOT the dev
# container. After flashing, restart the gateway (tunslip6 / connect-router),
# tap the Firefly reset, and confirm `ping6 fd00::1`.
#
# Usage:
#   ./flash-br.sh [PORT] [BOARD]
#     PORT   serial device (default /dev/ttyUSB0)
#     BOARD  firefly | firefly-reva  (default firefly)
#
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

PORT="${1:-/dev/ttyUSB0}"
BOARD="${2:-firefly}"

HERE="$(cd "$(dirname "$0")" && pwd)"
CONTIKI="$HERE/.."
BIN="$CONTIKI/examples/rpl-border-router/build/zoul/$BOARD/border-router.bin"
BSL="$CONTIKI/tools/cc2538-bsl/cc2538-bsl.py"
LOAD_ADDR="0x00202000"   # CC2538 flash image base (objdump LOAD segment)

if [ ! -f "$BIN" ]; then
  echo "ERROR: $BIN not found."
  echo "Build it in the container: make -C examples/rpl-border-router TARGET=zoul BOARD=$BOARD ..."
  exit 1
fi
if [ ! -e "$PORT" ]; then
  echo "ERROR: serial $PORT not present. Attach the Firefly: usbipd attach --wsl --busid <id>."
  exit 1
fi

echo "=== Flashing Firefly border-router: board=$BOARD port=$PORT @ $LOAD_ADDR ==="
python3 "$BSL" -e -w -v -b 460800 -a "$LOAD_ADDR" -p "$PORT" "$BIN"
echo ""
echo "Done. Next: restart the gateway (make ... connect-router / tunslip6), tap the"
echo "Firefly reset so it re-requests the prefix, then confirm 'ping6 fd00::1'."
