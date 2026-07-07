#!/bin/bash
#
# Build the multi-run benchmark firmwares for the nRF52840-DK and collect the
# .hex here (local-tests/bench/). Each firmware repeats a full operation
# BENCH_ITERS times, times it, and prints one incremental-Welford stats line per
# cycle (last line = full result: n / mean / sample-stddev / min / max). See
# bench-stats.h + README.
#
# Matrix: {sw uECC, CC310 hardware} x {CSMA, TSCH}. The label baked into each
# stats line encodes the config, so a pasted "last line" is self-identifying.
#
# Iterations per run default to 30; override for the whole build, e.g.:
#   BENCH_ITERS=100 ./build-bench-rungs.sh
#
#   CSMA variants run on the current Firefly gateway (CSMA border router).
#   TSCH variants need the WHOLE path on TSCH: a TSCH Firefly border router
#   (coordinator) + a TSCH-built responder. See README (TSCH bring-up).
#
# SECURITY NOTICE: Test credentials only. Never use in production.

set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
ARM="/home/joel/toolchains/arm-gcc/bin"
TOOLS="CC=$ARM/arm-none-eabi-gcc AS=$ARM/arm-none-eabi-gcc LD=$ARM/arm-none-eabi-gcc \
AR=$ARM/arm-none-eabi-ar OBJCOPY=$ARM/arm-none-eabi-objcopy NM=$ARM/arm-none-eabi-nm \
SIZE=$ARM/arm-none-eabi-size"
OBJCOPY="$ARM/arm-none-eabi-objcopy"

# EDHOC bench targets the bridged native responder (fd01::302:304:506:1, node 1).
SERVER_EP='-DEDHOC_CONF_SERVER_EP='"'"'"coap://[fd01::302:304:506:1]"'"'"''

# $1 app-dir, $2 base-name, $3 backend (sw|cc310|none), $4 mac (csma|tsch)
# backend=none: DTLS apps (mbedtls crypto, no os/services/ecc switch, no fd01
# responder -- they target setest at fd00::1 via their own defaults).
build_one() {
  local app="$1" base="$2" backend="$3" mac="$4"
  local dir="$HERE/$app"
  local extra="" label cfl
  if [ "$backend" = none ]; then label="$base-$mac"; else label="$base-$backend-$mac"; fi
  [ "$backend" = cc310 ] && extra="$extra ECC_HW_BACKEND=cc310"
  [ "$mac" = tsch ] && extra="$extra MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1"
  cfl="-DBENCH_LABEL='\"$label\"'"
  [ -n "${BENCH_ITERS:-}" ] && cfl="$cfl -DBENCH_ITERS=$BENCH_ITERS"
  case "$app" in edhoc-*) cfl="$SERVER_EP $cfl" ;; esac
  echo "=== build $app -> bench-$label ==="
  make -C "$dir" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= clean >/dev/null 2>&1 || true
  env CFLAGS="$cfl" make -C "$dir" TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= $extra $TOOLS
  "$OBJCOPY" -O ihex "$dir/build/nrf52840/dk/$app.nrf52840" "$HERE/bench-$label.hex"
  echo "  -> $HERE/bench-$label.hex"
}

# EDHOC+OSCORE handshakes: {sw, CC310} x {CSMA, TSCH}, -> native responder fd01::.
for be in sw cc310; do for m in csma tsch; do
  build_one edhoc-c5t-bench edhoc-c5t "$be" "$m"
  build_one edhoc-c5c-bench edhoc-c5c "$be" "$m"
done; done

# DTLS handshakes: {CSMA, TSCH} only (mbedtls crypto), -> setest fd00::1.
# NOTE: dtls-c509 is intentionally NOT built. The bench uses a CA-issued Type-2
# (natively CBOR-signed) C509 credential, which no python-mbedtls setest server
# can verify in the client-auth direction (Type-2 DTLS gap, task #16 /
# PLAN-c509-type2-dtls.md), so it cannot complete a handshake against setest. And
# DTLS reconstructs C509 to the identical 364 B X.509 DER before the TLS record,
# so on the wire dtls-c509 == dtls-x509 (a storage win, not a wire win). The
# dtls-c509-bench sources are kept (RPL/GET/TSCH configs in sync with x509) so it
# is ready IF Type-2 DTLS Phase 1 lands -- uncomment then.
for m in csma tsch; do
  build_one dtls-psk-bench  dtls-psk  none "$m"
  build_one dtls-x509-bench dtls-x509 none "$m"
  # build_one dtls-c509-bench dtls-c509 none "$m"   # blocked: see note above
done

echo ""
echo "=== benchmark firmwares built: ==="
ls -1 "$HERE"/bench-*.hex
