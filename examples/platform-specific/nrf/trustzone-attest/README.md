# P2 — RA-over-EDHOC with a TrustZone secure-world Root of Trust (nRF5340)

Phase P2 of the `draft-ietf-lake-ra` Contiki port (`CONTIKI-PORT-PLAN.md` /
`P2-TRUSTZONE-PLAN.md`): give the attestation Evidence a **hardware Root of Trust**
by moving the attestation key, the image measurement, and the signing into the
nRF5340 TrustZone-M **secure world**, so a compromised normal world cannot forge a
"good" measurement.

- **`secure-world/`** — a minimal Contiki instance that exposes the RoT as
  secure-gateway veneers: `tz-attest.c` (`tz_attest_build_evidence`,
  `tz_attest_public_key`). It holds the attestation key, `measure()`s the NS image
  (`NS_ROM_ALIAS(NS_IMAGE_PRIMARY_PARTITION_OFFSET)` for `IMAGE_NS_CODE_SIZE`), and
  signs Evidence via the portable `os/services/attestation/ra-rot` core. NS pointers
  are validated with `cmse_check_address_range()` (the `tz-radio` pattern).
- **`normal-world/`** — the RA application + the **on-device P2 self-test**
  (`normal-world-attest.c`): compute the (public) binder, call the secure veneer to
  get Evidence about this image, fetch the public key, appraise, and print
  `=== TZ-ATTEST P2 PASSED ===`.

## Test cases
1. **Host RoT-core test (runs today, no hardware):**
   `../../../../tests/2x-attestation/build-native-p2.sh` — 8/8, incl. the security
   properties: the measurement is produced by the RoT (not the caller), a **tampered
   image is detected** (`MEASUREMENT_MISMATCH`), the RoT signs honestly, and anti-relay
   holds. This validates the exact computation that runs inside `tz-attest`.
2. **On-device self-test (this example):** flash the merged firmware and watch the
   serial log for the `TZ-ATTEST P2 PASSED` banner — proves the NS↔S veneer, the
   secure measurement + signing, and NS-side appraisal work on the real split.
3. **Tamper test (on-device):** rebuild the normal world with a one-line change, keep
   the same expected/golden measurement at the (host-side or NS) Verifier, and confirm
   the appraisal now fails — the RoT measures the *changed* image.

## Build & run
```
# emulator first (nRF5340 model runs the S/NS split):
#   build the merged hex, then run in cooja-ng (see below).
make TARGET=nrf BOARD=nrf5340/dk/application         # builds secure + normal, merges

# nRF5340-DK (in hand): flash the merged hex and read the serial log.
make upload PORT=/dev/ttyACM0
make login  PORT=/dev/ttyACM0                        # look for TZ-ATTEST P2 PASSED
```
Notes:
- Needs the ARM toolchain and `srec_cat` (the two-image merge, as in the sibling
  `examples/platform-specific/nrf/trustzone`).
- The RoT signer is Monocypher Ed25519 for bring-up (matches the host test); a
  CC312/uECC backend + sealed on-device key generation are the follow-up
  (`P2-TRUSTZONE-PLAN.md` §6, §9-b).
- If the Evidence does not fit EDHOC's `EAD_3` in the P1b live run, convey it
  post-handshake over OSCORE (draft Appendix B) — carried-over Tier-B finding #4.

## Status
- **RoT core (`ra-rot`) + host test: done (8/8).**
- **Secure veneer (`tz-attest`) + example: written**, following the validated
  `tz-radio` secure-service pattern; the TrustZone firmware **build + on-device run is
  the nRF5340-DK bring-up step** (P2a/P2c in `P2-TRUSTZONE-PLAN.md`).

SECURITY NOTICE: Test vectors only. Never use in production.
