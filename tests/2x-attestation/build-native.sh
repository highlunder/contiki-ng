#!/bin/bash
# Standalone (host gcc) build + run of the RA-over-EDHOC P0 KATs -- the quick
# validation of the os/services/attestation codec against draft-ietf-lake-ra
# Appendix A, independent of the Contiki build system. Exits non-zero on failure.
# (ra-binder.c pulls os/lib/sha-256 for the P1 binder, hence the stubs + sha-256.c.)
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(cd "$HERE/../.." && pwd)
A=$C/os/services/attestation
OUT=$(mktemp -d)/ra-kat
# stubs must precede os/ so contiki.h / uip.h / cc.h resolve to the host stubs.
gcc -Wall -Wextra -std=c99 -I "$HERE/stubs" -I "$A" -I "$C/os" \
  "$HERE/test-attestation.c" \
  "$A/ra-cbor.c" "$A/ra-cose.c" "$A/ra-eat.c" "$A/ra-ead.c" "$A/ra-binder.c" \
  "$C/os/lib/sha-256.c" \
  -o "$OUT"
"$OUT"
