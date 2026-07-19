#!/bin/bash
# Standalone (host gcc) build + run of the RA-over-EDHOC P1 crypto tests: the
# attestation binder (os/lib SHA-256 + HKDF) and the full Attester->Verifier
# Evidence flow (Monocypher Ed25519 as the pluggable sign/verify backend).
# Exits non-zero on any failure.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(cd "$HERE/../.." && pwd)
A=$C/os/services/attestation
MC=$C/tests/21-security-protocols/cc310-bringup/ec25519-bench-sw/monocypher
OUT=$(mktemp -d)/ra-kat-p1
# stubs must precede os/ so contiki.h / uip.h / cc.h resolve to the host stubs.
gcc -Wall -Wextra -std=c99 \
  -I "$HERE/stubs" -I "$A" -I "$C/os" -I "$MC" \
  "$HERE/test-attestation-p1.c" \
  "$A/ra-cbor.c" "$A/ra-cose.c" "$A/ra-eat.c" "$A/ra-ead.c" "$A/ra-binder.c" \
  "$A/ra-attester.c" "$A/ra-verifier.c" \
  "$C/os/lib/sha-256.c" \
  "$MC/monocypher.c" "$MC/monocypher-ed25519.c" \
  -o "$OUT"
"$OUT"
