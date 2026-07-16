# On-device C509 revocation codec — host tests

Validates the self-contained on-device C509 **revocation** modules in
`os/services/c509/` against the `c509rev` reference implementation's KAT vectors:

- `c509-crl.{c,h}` — C509 CRL parser + binary-search revocation check
  (draft-liao-cose-c509-revocation, "C509 CRL"; the exact, binary-searchable CRL
  vs a lossy Bloom CCRL).
- `c509-ocsp.{c,h}` — C509 OCSP **response** status codec (Error / Basic /
  Simple; look up a cert's status by (issuerCertHash, serialNumberHash)).
- `c509-rev-verify.{c,h}` — locate the signed TBS + signature of a flat-array
  revocation object (CRL / signed OCSP req/resp) and Ed25519-verify it.
- `c509-cbor-lite.{c,h}` — the shared minimal read-only CBOR walker all three use
  (no `os/services/c509/cbor.h`, so no `cbor_major_type_t` collision with
  `os/lib/cbor.h`; links into EDHOC/OSCORE/DTLS clients).

## Two test binaries
`c509-crl-hosttest.c` — the CRL codec.
`c509-ocsp-hosttest.c` — the OCSP codec + the rev-verify **locate/handoff** path
(with a stub Ed25519 so it links without mbedTLS; it byte-checks that the exact
TBS+signature are handed to the verifier).

The **real Ed25519 signature KAT** (verifying `CRL_NO_REVOKED` against the
published crlocsp-ca public key, plus a flipped-key negative control) runs inside
the Contiki `tests/07-c509` native suite, where mbedTLS SHA-512 is linked
(`run_revocation_test()`): look for `REVOCATION: CRL + OCSP + Ed25519-verify
tests OK`.

`c509-crl.c` is self-contained (stdint/stddef/string only; no CBOR/ASN.1 library,
no `os/services/c509/cbor.h`), so it links into an EDHOC/OSCORE/DTLS client with
no `cbor_major_type_t` collision, like `c509-chain`/`c509-csr-*`/`x509-csr-parse`.

## What it checks
KATs copied verbatim from the `c509rev` tests (`src/crl.rs`, `src/ocsp_resp.rs`):
- `CRL_REVOKED` — 6 revoked certs (serials 0x1122/1234/3344/5566/5678/9abc,
  `serialNumberLength`=2, `dateLength`=3, sorted, with reason bytes). Confirms the
  control parse, all six positive lookups, negative lookups, and reason-byte reads.
- `CRL_NO_REVOKED` — empty `revokedCertsList` (null) → `n_entries`=0; and the
  TBS/signature locator (TBS = `full[1 .. len-66]`, sig = last 64 bytes).
- `BASIC_RESP` / `SIMPLE_RESP` — OCSP status lookups: Good, NotIssued, Unknown,
  and Revoked (revocationTime 1740844800, reason 4); cross-issuer misses.
- Error response `820006` → type 0, responseStatus 6.

## Build + run (host)
```sh
gcc -Wall -Wextra -I../../os/services/c509 -o c509-crl-hosttest  c509-crl-hosttest.c
gcc -Wall -Wextra -I../../os/services/c509 -o c509-ocsp-hosttest c509-ocsp-hosttest.c
./c509-crl-hosttest        # expect: ALL TESTS PASSED (0 failures)
./c509-ocsp-hosttest       # expect: ALL TESTS PASSED (0 failures)
```
Each test `#include`s the module `.c` directly, so no separate link step.
Warning-free under `-Wall -Wextra`.

The real Ed25519 CRL-signature KAT runs in `tests/07-c509` (native), which links
mbedTLS SHA-512 — `run_revocation_test()` prints `REVOCATION: CRL + OCSP +
Ed25519-verify tests OK`.

## Status
PASS 2026-07-16. On-device C509 revocation codec for the LICE/LRev revocation
follow-up (the paper's Tier-1 eval gap — the Rust `c509rev` impl is host-only):
- CRL parse + binary-search lookup — DONE (`c509-crl`).
- OCSP response status codec — DONE (`c509-ocsp`).
- OCSP **request** builder, Simple + Unsigned + **Signed (type 1)** — DONE
  (`c509-ocsp-req`; the host test reproduces the draft `SIMPLE_REQ` (51 B),
  `UNSIGNED_REQ` (132 B), and the signed request's `TBS` (from `SIGNED_REQ_NO_CERT`,
  209 B) byte-for-byte; the signed request's ECDSA-P256 signing + verify round-trip
  runs in 07-c509 with a tampered-TBS negative control).
- CRL/OCSP signature verify, **Ed25519 + ECDSA-secp256r1-SHA256** — DONE
  (`c509-rev-verify` + `c509-rev-verify-ecdsa`; `c509_rev_sig_alg()` picks the
  algorithm). Real KATs in 07-c509: the Ed25519 published-key CRL and a
  deterministic P-256 CRL from `idc509rev` `examples/ecdsa_crl_vector`, each with
  a flipped-key negative control.
- setest server scenario (server side) — DONE (`setest/modules/revocation.py`,
  scenario `crlocsp`: GET /crl + POST /ocsp; smoke test cross-verified via c509rev).
- Next: Contiki integration of the revocation check into the DTLS/EDHOC validation
  path (an app-level CRL store/fetch) + CC310 energy measurement (Tier-1 hardware).
