#!/bin/bash
# Standalone (host gcc) build + run of the P1b EDHOC-glue test: the RP handler
# (ra-edhoc-glue) appraising RA Evidence delivered as an edhoc_ead_data_t, using
# the real EDHOC EAD type (header-only) + Monocypher Ed25519. Non-zero on failure.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(cd "$HERE/../.." && pwd)
A=$C/os/services/attestation
E=$C/os/net/security/edhoc
MC=$C/tests/21-security-protocols/cc310-bringup/ec25519-bench-sw/monocypher
OUT=$(mktemp -d)/ra-kat-p1b
gcc -Wall -Wextra -std=c99 \
  -I "$HERE/stubs" -I "$A" -I "$C/os" -I "$E" -I "$MC" \
  "$HERE/test-attestation-p1b.c" \
  "$A/ra-cbor.c" "$A/ra-cose.c" "$A/ra-eat.c" "$A/ra-binder.c" \
  "$A/ra-attester.c" "$A/ra-verifier.c" "$A/ra-edhoc-glue.c" \
  "$C/os/lib/sha-256.c" \
  "$MC/monocypher.c" "$MC/monocypher-ed25519.c" \
  -o "$OUT"
"$OUT"
