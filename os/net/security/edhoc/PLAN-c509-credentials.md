# C509 Credential Integration into EDHOC

**Goal:** Enable C509 (CBOR-encoded X.509) certificates as EDHOC authentication
credentials, replacing the current CCS/RPK-only model with standards-compliant
certificate-based authentication as specified in RFC 9528 §3.5.2 and
draft-ietf-cose-cbor-encoded-cert.

## Status Summary (2026-06-03)

| Phase | Description | Status |
|-------|-------------|--------|
| A — c5t (hash-by-reference) | Native cooja, both nodes | **PASS** (20s sim) |
| B — c5c (inline cert delivery) | Native cooja, both nodes | **PASS** (20s sim) |
| C — nRF52840 emulation | Method 0 baseline + c5t + c5c on nRF52840 | **PASS** (11s sim) |

**Phase C result (2026-06-03):** All three nRF52840 tests pass with the fixed
cooja-ng emulator (LDRD/STRD, VFP double-precision, SUBS/SBC fixes landed on
c509-experimental). Four additional firmware fixes were required for c5c:

| Fix | Root cause | Change |
|-----|-----------|--------|
| C1 — RPL parent eviction | CSMA retries during ECDSA spike ETX > 512 | `RPL_MRHOF_CONF_MAX_LINK_METRIC 16384` |
| C2 — Competing EDHOC session | CoAP timeout fires before MSG_2 arrives | `EDHOC_CONF_ATTEMPTS 1` |
| C3 — Server session timeout | Default 10s too short for nRF ECDSA | `EDHOC_CONF_TIMEOUT 60000` (server) |
| C4 — MSG_3 never transmitted | Radio in TXIDLE after blocking ECDSA | Deferred MSG_3 via EVT_POST in edhoc-client.c |

OSCORE Master Secret matched on both sides:
`b3 01 15 58 b6 66 ae ab dd ed 7d 0a 06 86 7d d6`

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

- [x] Add `edhoc-c509-client/` and `edhoc-c509-server/` directories
  - `EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T` in project-conf.h
  - `EDHOC_CONF_MAX_CRED_LEN 256` for C509 cert headroom
  - Both apps use `edhoc-cred-c509-test.h` (cert from vectors.h, same cert for both peers)
- [x] Add Cooja sim script `04-edhoc-c509-c5t.csc` (Method 0, TIMEOUT 120s)
- [x] Both binaries build warning-free for cooja target
- [x] Cooja end-to-end run: PASSED (20s sim). Both nodes report "c5t: peer key found
  via cert hash". OSCORE Master Secret matches: 9e 05 8b 38 3f 03 80 4e e1 31 89 80 7e 80 63 44.
  Three bugs fixed in the process (see commit 102deba87).

---

### Phase B: c5c Inline Cert Delivery

#### B1 — Add c5c configuration

**File:** `os/net/security/edhoc/edhoc-config.h`

- [x] Add `EDHOC_CRED_C509_C5C 5` auth type constant (moved before the #if check it governs)
- [x] Add `EDHOC_COSE_HEADER_C5C 25` (c5c = 25 from C509 draft-11 IANA table)
- [x] `EDHOC_MAX_ID_CRED_LEN` for c5c mode: 256 bytes (covers 164-byte c5c ID_CRED)
  - **Bug fixed**: credential type constants were defined AFTER the `#if EDHOC_AUTHENT_TYPE`
    guard that used them, so the condition always evaluated as `(0==0)=TRUE`, forcing
    `EDHOC_MAX_ID_CRED_LEN=32` for all modes. Moving the constants before the guard fixes this.

#### B2 — Extend send path for c5c

**File:** `os/net/security/edhoc/edhoc-cred-c509.c`

- [x] `edhoc_c509_generate_id_cred_c5c(const cose_key_t *key, uint8_t *out, size_t out_sz)`
  - Builds CBOR: `{ 25: h'<raw C509 bytes>' }`

**File:** `os/net/security/edhoc/edhoc.c`

- [x] In `edhoc_generate_id_cred_x()`: add branch for `EDHOC_CRED_C509_C5C`
  - Call `edhoc_c509_generate_id_cred_c5c()` — returns `{ 25: cert_bytes }`
- [x] In `edhoc_generate_cred_x()`: same as c5t — return raw C509 bytes

#### B3 — Extend receive path for c5c

**File:** `os/net/security/edhoc/edhoc-msgs.c`

- [x] In `edhoc_get_key_id_cred_x()`: add map-key dispatch for `25` (c5c)
  - `parse_c5c_credential(reader, key)`:
    - Read COSE_C509: bstr (single cert)
    - Call `edhoc_c509_extract_pub_key()` to get EC public key
    - Store cert pointer in key->c509_data (needed for later id_cred_x regeneration)
    - Fill `key` struct — no key store lookup needed (key is inline)
    - Return `EDHOC_SUCCESS`
- [x] **Bug fixed**: `edhoc_get_key_id_cred_x` return type `int8_t` overflowed when
  returning 164 (c5c ID_CRED_x size). Changed to `int16_t`.
- [x] **Bug fixed**: `copy_id_cred_x_to_output` return type also changed to `int16_t`.
- [x] **Bug fixed**: `key_result` variable in `edhoc_authenticate_msg` widened to `int16_t`.

#### B4 — Payload buffer sizing

**File:** `os/net/security/edhoc/edhoc-config.h`

- [x] `EDHOC_MAX_PAYLOAD_LEN`: applications must set `EDHOC_CONF_MAX_PAYLOAD_LEN ≥ 320`
  for c5c (MSG_2 = 266 bytes, MSG_3 = 239 bytes). Default 256 is insufficient.
  - **Bug fixed**: `edhoc-client.c` stored rx_sz as `(uint8_t)rx_sz`, truncating 266 → 10.
    Changed to `(uint16_t)rx_sz`.
- [x] `EDHOC_MAX_BUFFER`: applications must set `EDHOC_CONF_MAX_BUFFER ≥ 512` for c5c
  (TH_2 input = TH(34) + PLAINTEXT_2(231) + CRED_R(159) = 424 bytes).

#### B5 — Optional: cert validation hook

- Deferred to future work. Trust-on-first-use (no chain validation) is the default.

#### B6 — Tests

- [x] Add `tests/21-security-protocols/edhoc-c5c-client/` and `edhoc-c5c-server/`
  - `EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C`, `EDHOC_CONF_MAX_PAYLOAD_LEN 320`,
    `EDHOC_CONF_MAX_BUFFER 512`
- [x] Add `cooja-ng/configs/edhoc-c509-c5c.json`
- [x] Cooja end-to-end run: **PASSED** (20s sim). OSCORE Master Secret matches:
  `93 26 f1 e9 56 7b 77 19 91 e8 ef 78 ed 3f 64 a8`

**nRF52840 emulation note (updated 2026-06-02)**: An earlier session attributed
nRF52840 EDHOC failures to a "FAST_MULT_ASM_8 emulation bug". This claim predates
the emulator fixes landed in cooja-ng `c509-experimental` (LDRD/STRD, VFP, SUBS/SBC).
The nRF52840 EDHOC test must be re-run — see Phase C below.

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

- [x] `07-c509` unit tests still pass (3/3 SUCCESS, no warnings)
- [ ] `21-security-protocols/01-edhoc-tests-cooja-method0.csc` still passes — deferred to Phase C (requires Cooja / cooja-ng run)
- [x] New `edhoc-c509-c5t.json` cooja-ng test PASSES: full MSG_1/2/3, c5t lookup both sides, OSCORE match
- [x] No new compiler warnings (client + server build clean for cooja target)
- [ ] `EDHOC_MAX_CRED_LEN` increase verified safe on nRF52840 stack profile — deferred to Phase C

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

---

## Phase C: nRF52840 Emulation Validation

**Goal:** Confirm that EDHOC Method 0 and C509 c5t/c5c credential modes work on
emulated nRF52840 hardware (cooja-ng `c509-experimental`) after the 2026-06-02
emulator bugfixes.

**Prerequisites:** cooja-ng `c509-experimental` with LDRD/STRD, VFP double-precision,
SUBS/SBC, RNG, and pending-RX buffer fixes applied (all landed 2026-06-02).
The `edhoc-method0-nrf52840.json` config runs native cooja server + nRF52840 client.

### C1 — Method 0 baseline (plain EDHOC, no C509)

- [x] Build `edhoc-test-client` for nRF52840 target
- [x] Run `cooja-ng/configs/edhoc-method0-nrf52840.json`
- [x] OSCORE Master Secret matches between native server and nRF52840 client
  Result: PASS at 10.761s simulated (2026-06-03)

### C2 — C509 c5t on nRF52840 (native server ↔ nRF52840 client)

- [x] Build `edhoc-c509-client` for nRF52840 target (EDHOC_CONF_SERVER_EP fixed to native cooja address)
- [x] Build `edhoc-c509-server` for cooja (native) target
- [x] Created `cooja-ng/configs/edhoc-c509-c5t-nrf52840.json`
- [x] OSCORE Master Secret matches; no ERRs
  Result: PASS at 10.786s simulated (2026-06-03)

### C3 — C509 c5c on nRF52840 (native server ↔ nRF52840 client)

- [x] Build `edhoc-c5c-client` for nRF52840 target
- [x] Build `edhoc-c5c-server` for cooja target (EDHOC_CONF_TIMEOUT 60000 added)
- [x] Created `cooja-ng/configs/edhoc-c509-c5c-nrf52840.json`
- [x] OSCORE Master Secret matches; no ERRs
  Result: PASS at 11.034s simulated (2026-06-03)

**Bugs fixed during C3:**
1. `edhoc-c5c-client/project-conf.h`: RPL_MRHOF_CONF_MAX_LINK_METRIC 16384 — CSMA congestion during MSG_1/MSG_2 exchange spiked ETX above default 512, evicting the parent before MSG_3 could be sent.
2. `edhoc-c5c-client/project-conf.h`: EDHOC_CONF_ATTEMPTS 1 — CoAP retransmit timer fires before MSG_2 completes (6LoWPAN fragmentation delay). With default ATTEMPTS=2, a second conflicting EDHOC session started while the first was still in progress.
3. `edhoc-c5c-server/project-conf.h`: EDHOC_CONF_TIMEOUT 60000 — default 10s server timeout expired before MSG_3 arrived from the ARM client (which requires ECDSA computation + fragmented delivery).
4. `os/net/security/edhoc/edhoc-client.c`: MSG_3 send deferred via EVT_POST — the blocking ECDSA computation left the nRF52840 radio in TXIDLE state; calling coap_send_request immediately caused CSMA to fail silently. Posting EVT_POST instead of calling edhoc_client_post_blocks() directly allows a Contiki event loop iteration, letting radio_process restore the radio to RX before the CSMA CCA attempt.

### C4 — Stack profile on nRF52840

- [ ] Measure peak stack depth during EDHOC Method 0 on nRF52840
- [ ] Confirm `EDHOC_MAX_CRED_LEN=256` does not overflow 256KB RAM budget
- [ ] (Optional) measure c5t and c5c stack separately (c5c MSG_2 is 266 bytes)

### Configs needed

| Config | Server | Client | Notes |
|--------|--------|--------|-------|
| `edhoc-method0-nrf52840.json` | native cooja | nRF52840 | Already exists |
| `edhoc-c509-c5t-nrf52840.json` | native cooja | nRF52840 | To be created |
| `edhoc-c509-c5c-nrf52840.json` | native cooja | nRF52840 | To be created |
