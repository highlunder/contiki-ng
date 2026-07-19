#!/bin/bash
# Standalone (host gcc) build + run of the RA-over-EDHOC P0 KATs -- the quick
# validation of os/services/attestation against draft-ietf-lake-ra Appendix A,
# independent of the Contiki build system. Exits non-zero on any KAT failure.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
C=$(cd "$HERE/../.." && pwd)
A=$C/os/services/attestation
OUT=$(mktemp -d)/ra-kat
gcc -Wall -Wextra -std=c99 -I "$A" \
  "$HERE/test-attestation.c" \
  "$A/ra-cbor.c" "$A/ra-cose.c" "$A/ra-eat.c" "$A/ra-ead.c" "$A/ra-binder.c" \
  -o "$OUT"
"$OUT"
