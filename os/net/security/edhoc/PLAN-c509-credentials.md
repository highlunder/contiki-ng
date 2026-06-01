# C509 Credential Integration into EDHOC

**Goal:** Enable C509 (CBOR-encoded X.509) certificates as EDHOC authentication
credentials, replacing the current CCS/RPK-only model with standards-compliant
certificate-based authentication as specified in RFC 9528 §3.5.2 and
draft-ietf-cose-cbor-encoded-cert.

**Branch:** `edhoc-merge` (on top of `c509_experimental`)

---

## Background

### What RFC 9528 requires for C509

- **CRED_x** (the credential used in transcript hashes and MAC context)  
  `CRED_x SHALL be the C509 certificate bytes` (§3.5.2 ¶2)

- **ID_CRED_x** (identifies the credential in the EDHOC message):
  - By hash (c5t): `{ 22 : COSE_CertHash }` — recommended for constrained use
  - By URI (c5u): `{ 23 : uri }` — out of scope
  - By value (c5c): `{ 25 : COSE_C509 }` — inline delivery, no pre-provisioning needed
  - (Values from draft-ietf-cose-cbor-encoded-cert IANA table: c5t=22, c5u=23, c5c=25)

- **c5t hash**: SHA-256/64 (8-byte truncation) is RECOMMENDED when EDHOC hash is SHA-256.
  COSE_CertHash = `[ hash_alg_id, bstr ]`, SHA-256/64 has alg id -15 (COSE "SHA-256/64").

- **c5c key**: Negative COSE header parameter from the C509 draft (exact value TBD at
  final publication; currently -1 in draft-ietf-cose-cbor-encoded-cert-11).

### What the EDHOC code currently does (credential path)

**Sending (own credential):**
```
edhoc_generate_cred_x()   →  CCS/CWT CBOR map  →  stored in ctx->buffers.cred_x
edhoc_generate_id_cred_x() → {4: kid} or full CCS → stored in ctx->buffers.id_cred_x
```
Both functions dispatch on `EDHOC_AUTHENT_TYPE` (compile-time).

**Receiving (peer credential):**
```
edhoc_get_key_id_cred_x()  → parse compact KID / {4:kid} / full COSE_Key
                           → fills cose_key_t with peer's EC public key
```
Result used to verify the peer's MAC or signature.

**Key storage:**
`cose_key_t` in `edhoc-key-storage.h` — holds KID, identity string, kty, crv,
and `ecc_key_t ecc` (priv + pub.x + pub.y, each 32 bytes for P-256).

---

## Strategy

Two phases ordered by value and implementation complexity:

### Phase A — c5t (hash-by-reference) — recommended first step

Message overhead: ~15 bytes for ID_CRED_x vs 128+ bytes for inline cert.
Both parties pre-provision each other's C509 cert out-of-band (same model as
current KID, but with cert instead of raw key).

Wire encoding:
```
CRED_x    = <raw C509 bytes>             (in transcript hash, MAC context)
ID_CRED_x = { 22: [-15, h'<8-byte SHA-256/64 of CRED_x>'] }
```

Key store: each `cose_key_t` entry gains a C509 cert reference (pointer + length).
On receive: hash incoming c5t, find matching entry by hash, extract public key
from the stored cert using `c509_parse_cert()`.

### Phase B — c5c (inline cert delivery) — enables cert discovery

Message overhead: cert size (~100-200 bytes) added to MSG_2/3.
Receiver does not need to pre-provision the peer's cert. Cert arrives inline;
receiver parses it, extracts the public key, optionally validates the signature.

Wire encoding:
```
CRED_x    = <raw C509 bytes>
ID_CRED_x = { 25: h'<raw C509 bytes>' }   (c5c = COSE header param 25)
```

---

## Detailed Implementation Plan

### Phase A: c5t Credential Support

#### A1 — Extend `cose_key_t` with C509 cert reference

**File:** `os/net/security/edhoc/edhoc-key-storage.h`

- [x] Add `const uint8_t *c509_data;` pointer field to `cose_key_t`
  - Points into application-owned static buffer; EDHOC does not own the memory
  - `NULL` means no C509 cert associated (CCS key entry)
- [ ] Add `size_t c509_len;` length field
- [ ] Update `edhoc_copy_key()` to copy the pointer (not deep-copy the cert bytes)
- [ ] Update `cose_print_key()` / `edhoc_print_key_info()` to log c509_len if non-zero

#### A2 — Add C509 credential configuration

**File:** `os/net/security/edhoc/edhoc-config.h`

- [x] Add `EDHOC_CRED_C509_C5T 4` auth type constant
- [x] Increase `EDHOC_MAX_CRED_LEN` default: 128 → 256 (or add
  `#ifndef EDHOC_CONF_MAX_CRED_LEN` override)
  - Rationale: typical secp256r1 C509 cert is 100-200 bytes; 256 gives margin
- [ ] For c5t mode, `EDHOC_MAX_ID_CRED_LEN` stays small (c5t is ~15 bytes), already
  covered by the KID-mode path (16 bytes). If using INCLUDE mode, 15 bytes fits.
  No change needed for Phase A.
- [x] Add `EDHOC_C5T_HASH_LEN 8` constant (SHA-256 truncated to 64 bits)
- [x] Add `EDHOC_COSE_HEADER_C5T 22` (COSE header param for c5t)
- [ ] Add `EDHOC_COSE_HASH_ALG_SHA256_64 (-15)` (SHA-256/64 alg id in COSE)

#### A3 — New file: `edhoc-cred-c509.h` / `edhoc-cred-c509.c`

**Location:** `os/net/security/edhoc/`

This module wraps the c509 service for EDHOC use.

- [x] `edhoc_c509_generate_cred_x(const cose_key_t *key, uint8_t *out, size_t out_sz)`
  - Returns `key->c509_data` bytes copied to `out` (= raw C509)
  - Returns 0 if `key->c509_data == NULL`
  
- [x] `edhoc_c509_generate_id_cred_c5t(const cose_key_t *key, uint8_t *out, size_t out_sz)`
  - Computes SHA-256 over `key->c509_data`, truncates to 8 bytes
  - Builds CBOR: `{ 22: [-15, h'<8 bytes>'] }`
  - Returns byte length of encoded map

- [x] `edhoc_c509_hash_cert(const uint8_t *c509, size_t len, uint8_t *hash_out, size_t hash_trunc_len)`
  - SHA-256 via Contiki's crypto layer (`os/lib/sha256.c` or Mbed TLS SHA-256)
  - Truncates to `hash_trunc_len` bytes
  
- [x] `edhoc_c509_extract_pub_key(const uint8_t *c509, size_t len, cose_key_t *key_out)`
  - Calls `c509_parse_cert()` → gets `cert.subject_pk` CBOR value
  - C509 encodes compressed EC point as `0xFD` + 32-byte x (secp256r1)
  - Recovers y-coordinate using ECC point decompression (see `x509_encode.c`)
  - Fills `key_out->ecc.pub.x` and `key_out->ecc.pub.y`
  - Sets `key_out->kty` and `key_out->crv` from the parsed pk_alg
  - Returns `EDHOC_SUCCESS` or error code

- [x] `edhoc_c509_lookup_by_hash(const uint8_t *hash, size_t hash_len, cose_key_t **key_out)`
  - Iterates the key storage list
  - For each entry with `c509_data != NULL`, calls `edhoc_c509_hash_cert()`
  - Compares truncated hash; returns matching entry or `EDHOC_ERR_KEY_NOT_FOUND`

#### A4 — Extend send path

**File:** `os/net/security/edhoc/edhoc.c`

- [x] In `edhoc_generate_cred_x()`: add branch for `EDHOC_AUTHENT_TYPE == EDHOC_CRED_C509_C5T`
  - Call `edhoc_c509_generate_cred_x()` — returns raw C509 bytes

- [x] In `edhoc_generate_id_cred_x()`: add branch for `EDHOC_AUTHENT_TYPE == EDHOC_CRED_C509_C5T`
  - Call `edhoc_c509_generate_id_cred_c5t()` — returns `{ 22: [-15, hash] }`

#### A5 — Extend receive path

**File:** `os/net/security/edhoc/edhoc-msgs.c`

- [x] In `edhoc_get_key_id_cred_x()`: add map-key dispatch for `22` (c5t)
  - `parse_c5t_credential(reader, key)`:
    - Read COSE_CertHash: CBOR array `[alg_id, hash_bstr]`
    - Validate alg_id is -15 (SHA-256/64) and hash is 8 bytes
    - Call `edhoc_c509_lookup_by_hash()` to find the matching key store entry
    - Extract public key from cert: `edhoc_c509_extract_pub_key()`
    - Fill `key` struct and return `EDHOC_SUCCESS`

#### A6 — Buffer size adjustments

**File:** `os/net/security/edhoc/edhoc-config.h`

- [x] `EDHOC_MAX_CRED_LEN`: increase default to 256 (C509 cert fits; guarded by
  `#ifndef EDHOC_CONF_MAX_CRED_LEN` so existing deployments can override down)
- [ ] Verify `EDHOC_MAX_PAYLOAD_LEN` (default 256) covers MSG_2/3 with C509 CRED
  (CRED_x is not transmitted inline in c5t mode, so payload stays small)

#### A7 — Build system

**File:** `os/net/security/edhoc/Makefile.edhoc`

- [ ] Add `MODULES += os/services/c509` when `EDHOC_CONF_CRED_C509` is defined
- [ ] Add `edhoc-cred-c509.c` to source list

#### A8 — Tests

**File:** `tests/21-security-protocols/` (new test variant)

- [ ] Add `edhoc-test-c509-client/` and `edhoc-test-c509-server/` directories
  - Configure `EDHOC_CONF_CRED_C509_C5T` in project-conf.h
  - Provision a test C509 certificate from `secure-endpoint-test-server/vectors.h`
- [ ] Add Cooja sim script `04-edhoc-c509-c5t.csc`
- [ ] Verify: MSG_1 sent, MSG_2 received and peer cert found by hash, MSG_3 sent,
  OSCORE context derived

---

### Phase B: c5c Inline Cert Delivery

#### B1 — Add c5c configuration

**File:** `os/net/security/edhoc/edhoc-config.h`

- [ ] Add `EDHOC_CRED_C509_C5C 5` auth type constant
- [x] Add `EDHOC_COSE_HEADER_C5C 25` (c5c = 25 from C509 draft-11 IANA table)
- [ ] `EDHOC_MAX_ID_CRED_LEN` for c5c mode must accommodate full cert:
  - When `EDHOC_AUTHENT_TYPE == EDHOC_CRED_C509_C5C`, set default `EDHOC_MAX_ID_CRED_LEN` to 256
  - The existing `#if EDHOC_AUTHENT_TYPE == EDHOC_CRED_KID` guard in edhoc-config.h
    already handles the small/large split; add a third branch

#### B2 — Extend send path for c5c

**File:** `os/net/security/edhoc/edhoc-cred-c509.c`

- [ ] `edhoc_c509_generate_id_cred_c5c(const cose_key_t *key, uint8_t *out, size_t out_sz)`
  - Builds CBOR: `{ -1: h'<raw C509 bytes>' }`
  - If chain: `{ -1: [h'<cert1>', h'<cert2>', ...] }` — for Phase B, single cert only

**File:** `os/net/security/edhoc/edhoc.c`

- [x] In `edhoc_generate_id_cred_x()`: add branch for `EDHOC_CRED_C509_C5C`
  - Call `edhoc_c509_generate_id_cred_c5c()` — returns `{ -1: cert_bytes }`
- [x] In `edhoc_generate_cred_x()`: same as c5t — return raw C509 bytes

#### B3 — Extend receive path for c5c

**File:** `os/net/security/edhoc/edhoc-msgs.c`

- [x] In `edhoc_get_key_id_cred_x()`: add map-key dispatch for `-1` (c5c)
  - `parse_c5c_credential(reader, key)`:
    - Read COSE_C509: bstr (single cert) or CBOR array of bstr (chain — take index 0)
    - Call `edhoc_c509_extract_pub_key()` to get EC public key
    - Fill `key` struct — no key store lookup needed (key is inline)
    - Return `EDHOC_SUCCESS`

#### B4 — Payload buffer sizing

**File:** `os/net/security/edhoc/edhoc-config.h`

- [ ] Ensure `EDHOC_MAX_PAYLOAD_LEN` ≥ overhead + cert size (256 bytes)
  - For nRF52840 with block-wise CoAP, this is handled by fragmentation
  - For native tests, increase to 512 bytes under `EDHOC_CRED_C509_C5C`
  - Alternatively: document that applications must set `EDHOC_CONF_MAX_PAYLOAD_LEN`

#### B5 — Optional: cert validation hook

**File:** `os/net/security/edhoc/edhoc-cred-c509.h`

- [ ] Declare callback type:
  ```c
  typedef edhoc_error_t (*edhoc_c509_validate_fn_t)(const uint8_t *c509, size_t len);
  ```
- [ ] Add `edhoc_c509_set_validate_cb(edhoc_c509_validate_fn_t cb)` to register
  a validation function (checks cert signature against a trust anchor)
- [ ] Call it from `parse_c5c_credential()` before accepting the key
- [ ] Default (NULL callback): no chain validation — trust on first use

#### B6 — Tests

- [ ] Add `05-edhoc-c509-c5c.csc` Cooja sim with inline cert delivery
- [ ] Test heterogeneous case: initiator uses c5t, responder uses c5c

---

## Key Design Decisions

### D1 — C509 data ownership

`cose_key_t.c509_data` is a **pointer**, not an embedded buffer. The cert bytes
live in application static memory (e.g., `const uint8_t my_c509[] = {...};`).
EDHOC never frees or reallocates it.

Rationale: copying 200 bytes per key store entry would balloon MEMB allocation.
Existing `edhoc_copy_key()` copies the pointer — this is safe as long as the
application keeps the buffer alive for the session duration (always true for
static provisioning).

### D2 — SHA-256/64 implementation

Use `sha256_process()` / `sha256_done()` from `os/lib/sha256.c` (already a
Contiki-NG module). Truncate to `EDHOC_C5T_HASH_LEN` (8) bytes. This avoids
pulling in Mbed TLS SHA-256 separately and is available without DTLS enabled.

### D3 — EC point decompression for P-256

C509 stores compressed public keys with `0xFD` prefix + 32-byte x. To fill
`cose_key_t.ecc.pub.y`, we need to compute y from x over secp256r1. The
`x509_encode.c` code already does this (the `ec_expand_point()` logic used
when building DER SubjectPublicKeyInfo). Extract it into a shared helper in
`edhoc-cred-c509.c` rather than calling x509_encode, to avoid the 17KB
x509_encode.c dependency in the EDHOC build.

Alternative: expose a small `c509_decompress_point(x, y_out)` function in
the c509 service and call it from EDHOC. This is cleaner if c509 is always
compiled in when C509 creds are used.

### D4 — `EDHOC_MAX_CRED_LEN` increase

The current default of 128 bytes is too small for most C509 certs
(secp256r1 self-signed cert with subject CN+SAN is ~150-180 bytes).
Increasing to 256 bytes raises the stack frame of `generate_msg_2/3` by 128 bytes.
On nRF52840 with 256KB RAM this is acceptable. On very tight targets
(< 64KB), applications can set `EDHOC_CONF_MAX_CRED_LEN` back down.

### D5 — Compile-time vs. runtime credential type

Current code uses `#if EDHOC_AUTHENT_TYPE ==` compile-time selection. C509
follows the same pattern: one auth type per build. This is consistent with
the existing design and keeps code size minimal. Runtime negotiation is out
of scope.

---

## COSE Header Parameter Reference

| Param | Value | Use |
|-------|-------|-----|
| `kid` | 4 | Current KID-based auth |
| `x5t` | 34 | X.509 hash (RFC 9360) |
| `x5chain` | 33 | X.509 inline (RFC 9360) |
| `c5t` | 22 | C509 hash (C509 draft) |
| `c5c` / c5chain | 25 | C509 inline (C509 draft-11) |

---

## File Change Summary

| File | Change |
|------|--------|
| `edhoc-key-storage.h` | Add `c509_data` pointer + `c509_len` to `cose_key_t` |
| `edhoc-config.h` | New auth types, constants, buffer size increase |
| `edhoc.c` | Dispatch in `generate_cred_x` and `generate_id_cred_x` |
| `edhoc-msgs.c` | New map-key handlers for 22 (c5t) and -1 (c5c) |
| `edhoc-cred-c509.c` | **New** — all C509-specific logic |
| `edhoc-cred-c509.h` | **New** — API declarations |
| `Makefile.edhoc` | Add c509 module dependency |
| `edhoc-key-storage.c` | Minor — update `edhoc_copy_key`, `cose_print_key` |

---

## Phase A Completion Criteria

- [ ] `07-c509` unit tests still pass
- [ ] `21-security-protocols/01-edhoc-tests-cooja-method0.csc` still passes
- [ ] New `04-edhoc-c509-c5t.csc` test passes: full MSG_1/2/3 exchange with c5t
- [ ] No new compiler warnings
- [ ] `EDHOC_MAX_CRED_LEN` increase verified safe on nRF52840 stack profile

---

## Open Questions

- **Q1**: Confirmed: `c5c` = **25** per IANA table in draft-ietf-cose-cbor-encoded-cert-11
  in this workspace (line 692 of draft Markdown). This is a positive integer — no
  negative-label concerns. If the final RFC changes the value, update
  `EDHOC_COSE_HEADER_C5C` only.

- **Q2**: Should Phase B include cert chain validation against a pre-provisioned
  trust anchor CA certificate? The RFC says validation is the application's
  responsibility (§D.3), so the validation callback (B5) is the right hook;
  the EDHOC library itself remains validation-agnostic.

- **Q3**: For Phase B, should `ID_CRED_x` carry the full chain or just the EE cert?
  RFC §3.5.2 says CRED_x is only the end-entity cert even when the ID carries
  a chain. Start with single-cert (EE only) in Phase B; add chain support later.
