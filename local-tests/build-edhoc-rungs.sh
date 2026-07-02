#!/bin/bash
#
# Build the EDHOC+OSCORE OTA rungs (5-edhoc-c5t, 6-edhoc-c5c) for the nRF52840-DK
# and collect the .hex here (local-tests/). These REUSE the existing, already
# OTA-ready EDHOC clients (tests/21-security-protocols/edhoc-oscore-c5{t,c}-client
# -- plain RPL nodes that wait for node_is_reachable) with only the server
# endpoint repointed to the bridged native responder at coap://[fd01::1] (see
# ../../secure-endpoint-test-server/run-edhoc-gateway.sh). EDHOC_CONF_SERVER_EP is
# #ifndef-guarded in each client's project-conf.h, so we override it here without
# touching the Cooja default.
#
# EDHOC runs over CoAP (port 5683) to /.well-known/edhoc; OSCORE app traffic is on
# UDP 5686. Both go to the same server IP (fd01::1), reached through the Firefly.
#
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
TESTS="$HERE/../tests/21-security-protocols"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"
OBJCOPY="$ARM/arm-none-eabi-objcopy"

# Point the client at the bridged native responder. Its address is the native
# uIP node address = prefix + IID-from-LL-addr, i.e. fd01::302:304:506:1 for
# CONTIKI_NODE_ID=1 (NOT fd01::1, which is nobody, nor the fd01::100 tun host
# side) -- confirmed from the responder's "Added global IPv6 address" log line.
# The '"..."' idiom keeps the C string quotes intact through make's shell
# invocation (same trick the app Makefiles use for FW_ID); env CFLAGS is the
# initial value and the app Makefile's `CFLAGS +=` appends to it.
SERVER_EP_CFLAG="-DEDHOC_CONF_SERVER_EP='\"coap://[fd01::302:304:506:1]\"'"

build_one() {   # $1 = client app dir, $2 = output hex basename
  local app="$1" out="$2"
  local dir="$TESTS/$app"
  echo "=== build $app -> $out (SERVER_EP=coap://[fd01::1]) ==="
  make -C "$dir" TARGET=nrf52840 BOARD=dk clean >/dev/null 2>&1 || true
  env CFLAGS="$SERVER_EP_CFLAG" \
    make -C "$dir" TARGET=nrf52840 BOARD=dk $TOOLS
  "$OBJCOPY" -O ihex "$dir/build/nrf52840/dk/$app.nrf52840" "$HERE/$out.hex"
  echo "  -> $HERE/$out.hex"
}

build_one edhoc-oscore-c5t-client 5-edhoc-c5t
build_one edhoc-oscore-c5c-client 6-edhoc-c5c

echo ""
echo "=== EDHOC OTA rungs built: ==="
ls -1 "$HERE"/5-edhoc-c5t.hex "$HERE"/6-edhoc-c5c.hex
