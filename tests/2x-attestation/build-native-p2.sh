#!/bin/bash
# Standalone (host gcc) build + run of the P2 Root-of-Trust tests (ra-rot): the
# secure-world attestation core measures the target image + signs Evidence, and a
# tampered image is caught by the Verifier. os/lib SHA-256 + Monocypher Ed25519 as
# the RoT signer. Non-zero on failure.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(cd "$HERE/../.." && pwd)
A=$C/os/services/attestation
MC=$C/tests/21-security-protocols/cc310-bringup/ec25519-bench-sw/monocypher
OUT=$(mktemp -d)/ra-kat-p2
gcc -Wall -Wextra -std=c99 \
  -I "$HERE/stubs" -I "$A" -I "$C/os" -I "$MC" \
  "$HERE/test-attestation-p2.c" \
  "$A/ra-cbor.c" "$A/ra-cose.c" "$A/ra-eat.c" "$A/ra-binder.c" \
  "$A/ra-attester.c" "$A/ra-verifier.c" "$A/ra-rot.c" \
  "$C/os/lib/sha-256.c" \
  "$MC/monocypher.c" "$MC/monocypher-ed25519.c" \
  -o "$OUT"
"$OUT"
