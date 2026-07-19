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
| `ra-binder.{c,h}` | §5.3.3.1 | `attest_info` encoding (H_12 + HKDF derivation is P1) |

## Status (P0)
- **Done:** the encoders/decoders above; the P0 KAT (`tests/2x-attestation`)
  reproduces Appendix A byte-for-byte (12/12), matching the Rust impl.
- **P1 (next):** derive `attestation_binder_m3` from the EDHOC transcript (H_12 +
  HKDF), sign/verify Evidence via a backend (`os/net/security/cose` /
  `c509-rev-verify`), register the RA EAD handlers with the Contiki EDHOC impl
  (`edhoc_register_ead_handler`). See `CONTIKI-PORT-PLAN.md` §5, §7.
- **Not a signing/verifying service yet:** P0 is pure structure. No key handling,
  no crypto. `ra-cose` builds the to-be-signed bytes; the actual sign/verify is a
  P1 backend concern (§7-a: extend `cose_sign1_sign` for `external_aad`).

## Test
```
# standalone (host gcc), the primary P0 validation:
tests/2x-attestation/build-native.sh
# Contiki-integrated build:
cd tests/2x-attestation && make TARGET=native
```

SECURITY NOTICE: Test vectors only. Never use in production.
