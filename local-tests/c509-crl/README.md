# On-device C509 CRL revocation lookup — host test

Validates `os/services/c509/c509-crl.{c,h}` — the self-contained on-device C509
CRL parser + binary-search revocation check (draft-liao-cose-c509-revocation,
"C509 CRL"; the exact, binary-searchable CRL vs a lossy Bloom CCRL) — against the
`c509rev` reference implementation's published KAT vectors.

`c509-crl.c` is self-contained (stdint/stddef/string only; no CBOR/ASN.1 library,
no `os/services/c509/cbor.h`), so it links into an EDHOC/OSCORE/DTLS client with
no `cbor_major_type_t` collision, like `c509-chain`/`c509-csr-*`/`x509-csr-parse`.

## What it checks
Two KATs copied verbatim from `idc509rev/c509rev/src/crl.rs` tests:
- `CRL_REVOKED` — 6 revoked certs (serials 0x1122/1234/3344/5566/5678/9abc,
  `serialNumberLength`=2, `dateLength`=3, sorted, with reason bytes). Confirms the
  control parse, all six positive lookups, four negative lookups, and reason-byte
  reads (0x1122→6, 0x1234→1, 0x5678→0).
- `CRL_NO_REVOKED` — empty `revokedCertsList` (null) → parses with `n_entries`=0
  and every lookup returns "not revoked".

## Build + run (host)
```sh
gcc -Wall -Wextra -I../../os/services/c509 -o c509-crl-hosttest c509-crl-hosttest.c
./c509-crl-hosttest        # expect: ALL TESTS PASSED (0 failures)
```
The test `#include`s `c509-crl.c` directly, so no separate link step. Warning-free
under `-Wall -Wextra`.

## Status
PASS 2026-07-16 (all 30 checks). First piece of the on-device C509 revocation
codec for the LICE/LRev revocation follow-up (the paper's Tier-1 eval gap — the
Rust `c509rev` impl is host-only). Next: OCSP request/response codec + signature
verification, then a Contiki integration into the DTLS/EDHOC validation path.
