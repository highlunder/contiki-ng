#!/bin/bash
# Stage the H2 enrollment wall-clock firmware (PLAN §10.2): the /crts+/sen
# enrollment flow, C509 arm vs X.509 arm, on a real 2-node radio link. The client
# prints one [ENROLL-TIMING fw:.. arm:..] edhoc_ms=.. crts_sen_ms=.. total_ms=..
# block per run -- the direct on-silicon analogue of the original LICE Fig-5
# operation-timing box plots (enrollment EDHOC+C509 vs the X.509 baseline).
#
# Two-node direct link (server = RPL root + CA, client = DUT); no TOPO_ROLE.
# The C509 and X.509 arms of the SAME app share a build tree, so this cleans
# between them (else the second arm ships the first arm's objects).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
CONTIKI=$(cd "$HERE/../../.." && pwd)
ARM=${ARM:-/home/joel/toolchains/arm-gcc/bin}
FW_ID=${FW_ID:-$(date -u +%Y%m%d)}
# Statistical benchmark: N looped enrollments with mean/median/p95/sd (Exp H2).
# ENROLL_ITERS=1 reproduces the old single functional pass.
ENROLL_ITERS=${ENROLL_ITERS:-20}
CLIENT=tests/21-security-protocols/edhoc-oscore-crts-client
SERVER=tests/21-security-protocols/edhoc-oscore-crts-server

TC="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"

# build_one <appdir> <appname> <outname> <extra-make-vars...>
build_one() {
  local appdir="$1" appname="$2" outname="$3"; shift 3
  echo "=== $outname ==="
  make -C "$CONTIKI/$appdir" TARGET=nrf BOARD=nrf52840/dk clean >/dev/null 2>&1 || true
  make -C "$CONTIKI/$appdir" TARGET=nrf BOARD=nrf52840/dk MAKE_MAC=MAKE_MAC_TSCH \
      LDFLAGS_WERROR= FW_ID="$FW_ID" ENROLL_BENCH=1 ENROLL_ITERS="$ENROLL_ITERS" \
      "$@" $TC >/dev/null
  "$ARM/arm-none-eabi-objcopy" -O ihex \
      "$CONTIKI/$appdir/build/nrf/nrf52840/dk/$appname.nrf" "$HERE/$outname.hex"
  echo "    -> $HERE/$outname.hex"
}

# C509 arm (primary):
build_one "$CLIENT" edhoc-oscore-crts-client enroll-c509-client-dk
build_one "$SERVER" edhoc-oscore-crts-server enroll-c509-server-dk
# X.509 arm (comparison, fully-dynamic PKCS#10 up / X.509 DER down):
build_one "$CLIENT" edhoc-oscore-crts-client enroll-x509-client-dk ENROLL_X509_DYN=1
build_one "$SERVER" edhoc-oscore-crts-server enroll-x509-server-dk ENROLL_X509_DYN=1

echo "=== staged $(ls -1 "$HERE"/enroll-*.hex 2>/dev/null | wc -l) enrollment hex in $HERE ==="
