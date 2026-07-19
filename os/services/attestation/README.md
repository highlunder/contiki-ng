# os/services/attestation — Remote Attestation over EDHOC (draft-ietf-lake-ra)

On-device codec + service for **Remote Attestation over EDHOC**
(`draft-ietf-lake-ra`), the Contiki-NG port of the standalone Rust reference
implementation (`draft-ietf-lake-ra/lake-ra-impl`). This is **Phase P0** of
`CONTIKI-PORT-PLAN.md`: the portable codec, validated byte-for-byte against the
draft's Appendix A, with no EDHOC or hardware dependency yet.

## Files
| file | draft § | role |
|---|---|---|
| `ra-cbor.{c,h}` | — | deterministic CBOR writer + a small vendored reader (self-contained; no c509/mbedTLS dependency) |
| `ra-cose.{c,h}` | §5.3.3/§5.3.3.1 | COSE_Sign1 + Sig_structure (binder as `external_aad`) assemble/parse |
| `ra-eat.{c,h}` | §5.3.3 | EAT minimal-claim-set (nonce/ueid/measurements) encode/decode |
| `ra-ead.{c,h}` | §5.3 | Attestation_proposal / Attestation_request encode/decode |
| `ra-binder.{c,h}` | §5.3.3.1 | attestation binder: `attest_info` + **H_12 (SHA-256) + HKDF-Expand** (`binder_m3`) |
| `ra-attester.{c,h}` | §5.3.3 | build a transcript-bound signed Evidence (pluggable signer) |
| `ra-verifier.{c,h}` | §8.1 | appraise Evidence: nonce + transcript binder + signature + reference value (pluggable verifier) |
| `ra-edhoc-glue.{c,h}` | §5.3 | RP appraisal of raw EAD-value Evidence + the app EDHOC-handler pattern (decoupled from EDHOC) |

## Status (P0 done, P1 crypto core done)
- **P0 (codec):** the encoders/decoders; KAT reproduces Appendix A byte-for-byte
  (12/12), matching the Rust impl.
- **P1a (crypto core, done):** `binder_m3` derived from the real EDHOC transcript
  (`H_12 = H(H(msg1),msg2)` via `os/lib/sha-256` + HKDF-Expand); `ra-attester`
  builds a signed Evidence and `ra-verifier` appraises it, both with a **pluggable
  crypto backend** (`ra_sign_fn` / `ra_verify_fn`). Validated standalone
  (`build-native-p1.sh`, 11/11): HKDF vs RFC 5869 TC1, binder determinism +
  anti-relay, and the full Attester→Verifier flow (sign + appraise + all negative
  cases) using Monocypher Ed25519 as the test backend. The module compiles + links
  under the Contiki build.
- **P1b (EDHOC glue, done):** `ra-edhoc-glue` appraises the raw Evidence bytes an
  EDHOC EAD_3 item carries, with the app-side handler-registration pattern documented
  in `ra-edhoc-glue.h` (kept decoupled from EDHOC so the module stays self-contained).
  Validated standalone (`build-native-p1b.sh`, 4/4): Attester builds Evidence → RP
  `ra_glue_appraise` → PASS; relayed-transcript and stale-nonce both abort.
- **P1b live run (next):** build EDHOC client (Attester) + server (RP) apps that
  capture message_1/message_2 + ID_CRED_I, call `ra_attester_build_evidence` with a
  signer (uECC/CC310) and pass Evidence as `edhoc_generate_message_3` auth_data, and
  register `ra_glue_appraise` via `edhoc_register_ead_handler`; run the (I,BG) flow in
  cooja-ng. Watch the EDHOC EAD_3 buffer limit (the lakers finding #4 analog). See
  `CONTIKI-PORT-PLAN.md` §5, §7 and `P2-TRUSTZONE-PLAN.md`.
- **Crypto backend is pluggable, not built in:** on-device the signer is a platform
  RoT (uECC/CC310, or the nRF5340 TrustZone secure world in P2); the tests supply
  Monocypher. The measurement is a stand-in until the RoT measures the real image.

## Test
```
tests/2x-attestation/build-native.sh      # P0 codec KATs (host gcc)
tests/2x-attestation/build-native-p1.sh   # P1 crypto (binder + Evidence flow, host gcc)
cd tests/2x-attestation && make TARGET=native   # Contiki-integrated P0 build
```

SECURITY NOTICE: Test vectors only. Never use in production.
