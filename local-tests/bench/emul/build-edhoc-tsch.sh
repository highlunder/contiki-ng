#!/bin/bash
# Build the three EDHOC+OSCORE handshake variants (x509 / c5c / c5t), client+server,
# for the shared nrf platform with TSCH + Orchestra, for the C509-vs-X509 handshake-
# latency-over-TSCH comparison. Software ECC (uECC). Logs per app to /tmp.
#
# SECURITY NOTICE: Test credentials only. Never use in production.
set -e

TC=/home/joel/toolchains/arm-gcc/bin
TESTS=/home/joel/gemini_workspace/contiki-ng/tests/21-security-protocols
COMMON="TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 \
  CC=$TC/arm-none-eabi-gcc AS=$TC/arm-none-eabi-gcc LD=$TC/arm-none-eabi-gcc \
  AR=$TC/arm-none-eabi-ar OBJCOPY=$TC/arm-none-eabi-objcopy NM=$TC/arm-none-eabi-nm"

for app in edhoc-oscore-x509-server edhoc-oscore-x509-client \
           edhoc-oscore-c5c-server  edhoc-oscore-c5c-client \
           edhoc-oscore-c5t-server  edhoc-oscore-c5t-client; do
  echo "=== building $app ==="
  make -C "$TESTS/$app" $COMMON > "/tmp/build_$app.log" 2>&1
  rc=$?
  fw="$TESTS/$app/build/nrf/nrf52840/dk/$app.nrf"
  if [ $rc -eq 0 ] && [ -f "$fw" ]; then
    echo "OK  $fw ($(stat -c%s "$fw") bytes)"
  else
    echo "FAIL $app (rc=$rc) — see /tmp/build_$app.log"
  fi
done
