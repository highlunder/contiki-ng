# Native C509 Support: Comprehensive Plan

**Created:** 2026-06-03  
**Updated:** 2026-06-10 — Steps 1–4 COMPLETE (see Step 4 below); Steps 5–6 remaining  
**Branch:** edhoc-merge  
**Depends on:** PLAN-next-steps.md Steps 1–4 (all COMPLETE)

---

## Background and Motivation

C509 certificates (draft-ietf-cose-cbor-encoded-cert) come in four types:

| Type | Description | Signature over |
|------|-------------|----------------|
| 0 | DER-equivalent, explicitly tagged | DER TBSCertificate |
| 1 | DER-equivalent, implicitly tagged | DER TBSCertificate |
| 2 | **Natively signed C509** | CBOR-encoded TBS (fields 0–9) |
| 3 | DER-reconstructed (CBOR-encoded, same sig as DER) | DER TBSCertificate |

All current test credentials are **Type 3** — reconstructed from existing X.509 test certs by the Rust reference tool (`c509_demo_impl`). Type 3 lets us reuse standard PKI tooling to mint test certs and compress them. Type 2 is what a native C509 PKI actually produces: the certificate authority signs over the raw CBOR TBS rather than a DER encoding, so the cert is smaller and contains no DER artefacts (no OID wrappers, no ASN.1 length fields in the signature input).

**Why native Type 2 matters:**
- Correct representation of what constrained IoT PKI should look like in production
- Smaller on the wire: signature input is a compact CBOR array, not a DER TBSCertificate with OID tables embedded
- Type 2 certs cannot be reconstructed into valid DER (the signature would not verify), so any validation path that does DER reconstruction (currently the DTLS path) will silently break
- Required for the publication evaluation to claim "native C509 support"

**Key constraint:** `edhoc_c509_validate_self_signed()` already implements Type 2 validation (ECDSA over SHA-256(CBOR TBS)). The code is correct; the gap is test credentials, trust store integration, chain validation, and DTLS.

---

## Current State

### Works today
- Type 3 credentials in EDHOC c5t and c5c — all 9 Method/credential combinations pass on native Cooja and nRF52840-DK
- `edhoc_c509_validate_self_signed()` handles Type 2 ECDSA verification correctly
- `c509_parse_cert()` correctly sets `tbs_ptr`/`tbs_len` for all types (the byte range of fields 0–9, which is the correct TBS input for Type 2 verification)
- DTLS DER-reconstruction path: `x509_encode.c` converts Type 3 → DER (works for DTLS Mbed TLS)
- Rust reference impl: `c509_demo_impl` converts DER ↔ C509; extensible for Type 2 generation

### Missing
- **No Type 2 test credentials** — only Type 3
- **No trust anchor store** — EDHOC only validates self-signed certs; no CA chain
- **`c509_verify_signature()` is unimplemented** — `crypto_mbedtls.c` is a stub
- **`c509_verify_chain()` is a skeleton** — `validator.c` is unfilled
- **No time validity in EDHOC c5c path** — `c509_check_time()` exists but is unused
- **DTLS has no Type 2 path** — DER reconstruction produces an invalid-signature cert for Type 2

---

## Step 1 — Type 2 Test Credential Generation

Type 2 certs are natively signed: a CA generates a CBOR TBS for each leaf cert and signs it with ECDSA P-256 over SHA-256 of the raw CBOR TBS bytes. No DER involved.

### 1a — Rust tooling: `generate_native_certs` command

Add a new mode to `CBOR-certificates/c509_demo_impl/` (new binary or sub-command):

**Inputs:** CA private key scalar, leaf private key scalar, certificate metadata (serial, subject, validity, issuer) as command-line args or a TOML config file.

**Algorithm:**
1. Build the CBOR TBS array (fields 0–9 from draft §4.1):
   - type = 2 (integer)
   - serial = test value
   - issuer_alg = 0 (ECDSA-SHA256)
   - issuer = `{1: "Test CA"}` (common name)
   - not_before, not_after = Unix timestamps for a long validity window
   - subject = `{1: "Test Client"}` or `{1: "Test Server"}`
   - pk_alg = 1 (secp256r1)
   - subject_pk = compressed P-256 public key (33 bytes, `0x02`/`0x03` prefix → C509 uses `0xFD`/`0xFE`)
   - extensions = `[]` (empty, no extensions for test certs)
2. Serialise fields 0–9 as a CBOR array (the TBS)
3. Hash TBS with SHA-256
4. Sign hash with ECDSA P-256 using issuer private key; encode signature as 64-byte bstr (r ‖ s)
5. Append signature as field 10 to produce the full cert CBOR array
6. Emit: C hex array suitable for C header inclusion

**Output files:** `c509_native_ca.hex`, `c509_native_client.hex`, `c509_native_server.hex`

Also add a Rust unit test that verifies the generated cert: parses it back, extracts TBS, re-hashes, and ECDSA-verifies the signature.

### 1b — New C test credential header

Create `os/net/security/edhoc/edhoc-cred-c509-native-test.h`:

```c
/* CA keypair (self-signed Type 2 CA cert).  Never sent on wire in these tests;
 * only the public key is used as the trust anchor. */
extern const uint8_t c509_native_ca_cert[];
extern const size_t  c509_native_ca_cert_len;
/* Extracted P-256 public key from CA cert (pre-computed, for fast lookup). */
extern const uint8_t c509_native_ca_pubkey_x[32];
extern const uint8_t c509_native_ca_pubkey_y[32];

/* Client leaf cert (Type 2, signed by CA).  KID = 0x04. */
extern const cose_key_t auth_c509_native_client_template;  /* includes private key */

/* Server leaf cert (Type 2, signed by CA).  KID = 0x03. */
extern const cose_key_t auth_c509_native_server_template;  /* includes private key */

/* Attach cert bytes to a key struct (same pattern as c509_test_attach_cert). */
void c509_native_test_attach_cert(cose_key_t *key, bool is_client);
```

Use different KIDs (0x03 = server, 0x04 = client) so Type 2 and Type 3 test certs can coexist in a binary if needed.

### 1c — Key material choice

Use fresh P-256 keypairs generated by the Rust tool (not the RFC 9529 test vectors) because the RFC 9529 vectors are interop test vectors — mixing them with a new CA signature chain would be confusing. Generate two new keypairs and a CA keypair, commit the private scalars alongside the cert bytes so tests are reproducible.

---

## Step 2 — C509 Service Layer: Crypto and Chain Validator

### 2a — Implement `c509_verify_signature()` in `crypto_mbedtls.c`

The function stub exists. For Type 2 certs the algorithm is:

```
hash = SHA-256(cert.tbs_ptr[0 .. cert.tbs_len])
(r, s) = decode signature bstr (64 bytes: r ‖ s)
result = ECDSA-P256-verify(hash, r, s, issuer_pub_key)
```

`c509_cert_t.tbs_ptr` and `c509_cert_t.tbs_len` already correctly delimit fields 0–9 (the byte range captured by `c509_parse_cert()`), so no re-parsing is needed.

The existing `ecc_verify_hash()` call in `edhoc_c509_validate_self_signed()` is exactly the right primitive. Extract it into `c509_verify_signature()` so both code paths share an implementation.

For Types 0, 1, 3 (DER-equivalent): return `C509_ERR_UNSUPPORTED_TYPE`. These types require DER TBS reconstruction which belongs to `x509_encode.c`; do not conflate the two.

### 2b — Complete `c509_verify_chain()` in `validator.c`

The skeleton already exists. Fill in the loop:

```
for each cert in the chain (leaf → root):
    parse cert with c509_parse_cert()
    if cert_type != 2:
        return C509_ERR_UNSUPPORTED_TYPE
    check validity period with c509_check_time(reference_time)
    if not last cert:
        check basic_constraints.is_ca == true
    call c509_verify_signature(cert, issuer_pubkey)
    issuer_pubkey = c509_extract_pubkey(cert) for next iteration
    if issuer matches a trust anchor:
        return C509_SUCCESS
return C509_ERR_UNTRUSTED
```

Design decisions:
- Maximum chain depth controlled by `C509_CONF_MAX_CHAIN_DEPTH` (default 2: leaf + CA)
- Reference time: a compile-time `C509_CONF_REFERENCE_TIME` (Unix timestamp). Constrained devices lack clocks; tests set this to a time within the cert validity window. Set to 0 to disable time checking.
- Input: array of `(cert_bytes, cert_len)` pairs, or a single cert for self-signed cases

### 2c — Add time validity to EDHOC c5c parsing

In `edhoc-msgs.c` `parse_c5c_credential()`, after `edhoc_c509_extract_pub_key()`:
- Parse the inline cert bytes with `c509_parse_cert()`
- Call `c509_check_time(EDHOC_CONF_CERT_REFERENCE_TIME)` if `EDHOC_CONF_CERT_REFERENCE_TIME != 0`
- Log a warning if outside validity period; optionally return `EDHOC_ERR_CERTIFICATE_REJECTED`

Guard the time check with a Kconfig-style define so existing tests (Type 3, validity = some past date) continue to pass by leaving the define at 0.

---

## Step 3 — Static Trust Anchor Store

Constrained devices cannot maintain a dynamic trust store. A static array with a registration API is sufficient.

### 3a — Trust anchor type and API

New file `os/net/security/edhoc/edhoc-trust-store.h`:

```c
typedef struct {
    uint8_t pk_x[32];          /* issuer P-256 public key x */
    uint8_t pk_y[32];          /* issuer P-256 public key y */
    uint8_t kid[8];            /* 8-byte identifier (truncated SHA-256 of issuer cert) */
    uint8_t kid_len;
} c509_trust_anchor_t;

#define EDHOC_CONF_MAX_TRUST_ANCHORS 2

void edhoc_trust_store_init(void);
int  edhoc_trust_store_add(const c509_trust_anchor_t *anchor);
const c509_trust_anchor_t *edhoc_trust_store_find_by_kid(
    const uint8_t *kid, uint8_t kid_len);
const c509_trust_anchor_t *edhoc_trust_store_find_by_pubkey(
    const uint8_t *pk_x, const uint8_t *pk_y);
```

### 3b — Convenience API for setting the built-in C509 validator

Extend `edhoc-cred-c509.h` with:

```c
/* Register the built-in chain validator and populate the trust store.
 * anchors: array of trust anchors; count: number of entries (≤ EDHOC_CONF_MAX_TRUST_ANCHORS).
 * Also calls edhoc_set_cert_validator(edhoc_c509_validate_cert, NULL). */
void edhoc_set_c509_trust_store(const c509_trust_anchor_t *anchors, uint8_t count);
```

Rename/add alongside `edhoc_c509_validate_self_signed()`:

```c
/* Full chain validator: handles self-signed (Type 2) and CA-issued (Type 2) certs.
 * For CA-issued: calls c509_verify_chain() against the trust store. */
edhoc_error_t edhoc_c509_validate_cert(const uint8_t *c509, size_t c509_len, void *app_ctx);
```

`validate_self_signed` remains as an alias for backward compatibility.

### 3c — Test app trust store initialization

In the native Type 2 test apps (Step 4b), at startup:

```c
c509_trust_anchor_t ca_anchor;
memcpy(ca_anchor.pk_x, c509_native_ca_pubkey_x, 32);
memcpy(ca_anchor.pk_y, c509_native_ca_pubkey_y, 32);
/* kid = first 8 bytes of SHA-256(CA cert bytes) — pre-computed */
memcpy(ca_anchor.kid, c509_native_ca_kid, 8);
ca_anchor.kid_len = 8;
edhoc_set_c509_trust_store(&ca_anchor, 1);
```

---

## Step 4 — EDHOC Integration: Type 2 Test Apps ✅ DONE 2026-06-10

All 6 Method × credential-type combinations (Methods 0/1/2 × c5t/c5c) with
CA-issued Type 2 credentials pass end-to-end on cooja-ng native simulation,
including OSCORE context derivation and a protected CoAP GET/2.05-Content
exchange. Results logged in `cooja-ng/test-runs/TEST-LOG.md`
("2026-06-10 — Step 4: EDHOC Native Type-2 (CA-issued C509) end-to-end tests"):

| Config | Method | Cred type | Result | Sim time |
|---|---|---|---|---|
| `edhoc-native-c5t.json` | 0 (Sig\|Sig) | c5t | PASS | 20.637 s |
| `edhoc-native-c5c.json` | 0 (Sig\|Sig) | c5c | PASS | 20.672 s |
| `edhoc-native-m1-c5t.json` | 1 (Sig\|StaticDH) | c5t | PASS | 20.619 s |
| `edhoc-native-m1-c5c.json` | 1 (Sig\|StaticDH) | c5c | PASS | 20.672 s |
| `edhoc-native-m2-c5t.json` | 2 (StaticDH\|Sig) | c5t | PASS | 20.615 s |
| `edhoc-native-m2-c5c.json` | 2 (StaticDH\|Sig) | c5c | PASS | 20.672 s |

The validator logs `EDHOC-C509: validate_chain: cert verified by trust anchor 0`
and `Peer certificate accepted by validator` — functionally equivalent to the
"Type 2 — ECDSA chain check OK" wording anticipated below. 4a, 4b and 4c are
all complete; remaining work is Step 5 (DTLS native Type 2 path) and Step 6
(wire-size/performance comparison).

### 4a — Update `edhoc_c509_validate_cert()` for CA-issued Type 2

The current `edhoc_c509_validate_self_signed()` verifies the cert's own signature using its own public key (self-signed check). For CA-issued certs, the signature is from the CA, not the leaf.

Detection: parse the cert and compare issuer fields to subject fields (for Type 2, both are explicit CBOR). If they differ, the cert is CA-issued.

Logic:
```
parse cert
if issuer == subject:
    verify self-signature (existing logic)
else:
    find CA in trust store by matching issuer field hash or public key
    call c509_verify_chain([cert], trust_anchor.pk)
```

### 4b — New EDHOC+OSCORE test apps with Type 2 credentials ✅ DONE

Following the exact pattern of Method 0 c5t/c5c apps, create:

**`edhoc-method0-c5t-native-client/`** and **`edhoc-method0-c5t-native-server/`**
- `EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T`
- Use `auth_c509_native_client_template` / `auth_c509_native_server_template`
- Register `edhoc_set_c509_trust_store()` with CA trust anchor
- c5t: 8-byte hash sent; cert looked up locally → validator called on local copy
- Cooja-ng config + nRF52840-DK config

**`edhoc-method0-c5c-native-client/`** and **`edhoc-method0-c5c-native-server/`**
- `EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C`
- Same credentials; cert sent inline
- Validator called on the received cert bytes → chain check against CA
- Cooja-ng config + nRF52840-DK config

Success criteria: same OSCORE Master Secret on both nodes, cert validator logs "Type 2 — ECDSA chain check OK".

### 4c — Extend tests to Method 1 and Method 2 ✅ DONE

Once Method 0 native passes, clone the apps for Method 1 (I:Sig|R:StaticDH) and Method 2 (I:StaticDH|R:Sig) with Type 2 credentials. No new code changes should be needed — just new project-conf.h files pointing at the native credential templates.

---

## Step 5 — DTLS Native Type 2 Path

This is the most architecturally complex step. The DTLS path in `mbedtls-support.c` calls `x509_encode_cert()` to reconstruct DER from C509, then passes the DER to Mbed TLS. For Type 2 certs the reconstructed DER cert has an invalid signature (the cert was signed over CBOR TBS, not DER TBSCertificate) — Mbed TLS rejects it.

### 5a — Analysis: approaches

**Option A — Mbed TLS verify callback (recommended)**

Mbed TLS supports `mbedtls_ssl_conf_verify(cb, ctx)`. The callback receives the peer cert chain after Mbed TLS has parsed it and the result code of its own checks. We can:
1. Still reconstruct DER from C509 (so Mbed TLS can parse the cert structure and extract the public key for ECDH)
2. In the verify callback, clear the `MBEDTLS_X509_BADCERT_NOT_TRUSTED` and `MBEDTLS_X509_BADCERT_BAD_KEY` flags that arise from the invalid signature
3. Perform native C509 chain verification in the callback using `c509_verify_chain()`
4. Return 0 (accept) if our chain check passes, non-zero otherwise

Advantage: minimal Mbed TLS surgery; the ECDH key exchange path is untouched.  
Risk: need to carefully clear only the right flags and not suppress legitimate errors (expired cert, wrong key usage).

**Option B — Inject public key directly**

Bypass Mbed TLS' cert parsing entirely: extract the peer public key from the C509 cert directly and inject it into the Mbed TLS context. Handle authentication as a separate C509 chain check.

This requires understanding which Mbed TLS API surface is used for injecting a raw ECDH peer key — feasible but requires more investigation into the Mbed TLS internals used for DTLS-ECC.

Start with Option A; document Option B if A proves too fragile.

### 5b — Implement `COAP_DTLS_SEC_MODE_C509_NATIVE` in `mbedtls-support.c`

1. Add a new mode enum value (or detect automatically by checking the cert type field at offset 0 of the C509 bytes)
2. In the cert setup path: call `x509_encode_cert()` as before to get DER for Mbed TLS parsing
3. Register a `dtls_native_c509_verify_cb()` via `mbedtls_ssl_conf_verify()`
4. In the callback:
   - Parse the original C509 bytes (available via app context) with `c509_parse_cert()`
   - Call `c509_verify_chain()` against the configured trust store
   - Clear `MBEDTLS_X509_BADCERT_NOT_TRUSTED` from flags if our check passed
   - Return 0 if passed, 1 if failed
5. Add a `c509_native_trust_store_t` pointer to the DTLS security context struct

### 5c — DTLS test config with Type 2 credentials

Adapt `c509-dtls-*.json` configs (already existing from Phase A DTLS work):
- New client + server firmwares built with `COAP_DTLS_SEC_MODE_C509_NATIVE`
- Same native Type 2 test credentials from Step 1b
- CA trust anchor registered at startup

---

## Step 6 — Wire Size and Performance Comparison

Once Type 2 end-to-end works, collect data for the publication evaluation:

### 6a — Wire encoding comparison (EDHOC)

For Method 0 c5c:
- Type 3 CRED_x size: raw C509 cert bytes (same as Type 3 cert from DER reconstruction)
- Type 2 CRED_x size: native C509 cert bytes (should be smaller — no DER OID baggage in TBS)
- Difference: the `signature` field (field 10) changes format; `subject_pk` format changes slightly
- Measure: run `tshark` or inspect cooja-ng RF bytes for the c5c exchange

### 6b — Flash and RAM footprint

Using `arm-none-eabi-size` on nRF52840 DK builds:
- Method 0 c5c Type 3 vs Type 2: flash diff (should be small — same code paths, different data)
- DTLS Type 3 vs Type 2: note whether removing the x509_encode.c DER path saves flash

### 6c — Handshake timing on nRF52840

From existing simulation results (~11 s simulated for Method 0). Type 2 should be similar or slightly faster (smaller cert = fewer 802.15.4 frames). Measure:
- MSG_2 payload size (server's c5c cert)
- MSG_3 payload size (client's c5c cert)
- Total simulated time

Tabulate in a comparison table for the paper.

---

## Open Questions

**Q1 — CA key reuse:** Should the native Type 2 CA keypair reuse any existing test key scalars (for cross-checking with other implementations), or be freshly generated? Fresh generation is cleaner; reuse aids interop comparison.

**Q2 — Clock for time validity:** Constrained devices have no reliable clock. For EDHOC: compile-time `EDHOC_CONF_CERT_REFERENCE_TIME` (default 0 = disabled). For DTLS: Mbed TLS has `MBEDTLS_PLATFORM_TIME_ALT` (currently unused). Document that production deployments must supply a clock or accept TOFU.

**Q3 — DER reconstruction in DTLS Option A:** After x509_encode produces DER from a Type 2 cert, Mbed TLS will see a cert whose signature does not verify (because the sig was over CBOR TBS). Mbed TLS may reject the cert before even calling the verify callback. Need to test whether `mbedtls_ssl_conf_authmode(MBEDTLS_SSL_VERIFY_OPTIONAL)` is required during parsing, then switched back to `REQUIRED` once the verify callback handles it — or whether the callback path always fires regardless of the cert signature check outcome.

**Q4 — Type 2 in c5t:** c5t sends an 8-byte hash; both sides have the full cert locally. The local copy is looked up and its public key extracted. Validation is against the local copy. Does the validator need to chain-check the local copy, or is the trust anchor check deferred to provisioning time? Recommendation: chain-check at startup when the local cert is loaded, not per-handshake.

**Q5 — Rust tool scope:** Is a TOML-config-driven `generate_native_certs` command worthwhile, or is a simpler hard-coded test cert generator acceptable for now? The latter is faster to implement; the former is needed for production PKI tooling.

---

## Implementation Order

```
Step 1a (Rust Type 2 cert generation)
  └──→ Step 1b (C header with Type 2 test creds)
        └──→ Step 2a (c509_verify_signature impl)
              └──→ Step 2b (c509_verify_chain complete)
                    └──→ Step 3 (trust store API)
                          └──→ Step 4a (edhoc_c509_validate_cert chain support)
                                └──→ Step 4b (EDHOC Type 2 test apps — Method 0)
                                      └──→ Step 4c (Methods 1 + 2)
                                            └──→ Step 5 (DTLS Type 2 path)
                                                  └──→ Step 6 (comparison data)

Step 2c (time validity in c5c) — independent, insert after Step 2a
```

Critical path: 1a → 1b → 2a → 2b → 3 → 4a → 4b → 5 → 6.

---

## File Change Summary

| File | Change |
|------|--------|
| `CBOR-certificates/c509_demo_impl/src/` | New module: Type 2 cert generation |
| `os/net/security/edhoc/edhoc-cred-c509-native-test.h` | **NEW** — Type 2 test cred byte arrays |
| `os/services/c509/crypto_mbedtls.c` | Implement `c509_verify_signature()` |
| `os/services/c509/validator.c` | Implement `c509_verify_chain()` |
| `os/services/c509/validity.c` | Minor — wire `c509_check_time()` into validator |
| `os/net/security/edhoc/edhoc-trust-store.h` | **NEW** — trust anchor store API |
| `os/net/security/edhoc/edhoc-trust-store.c` | **NEW** — trust anchor store impl |
| `os/net/security/edhoc/edhoc-cred-c509.h` | Add `edhoc_c509_validate_cert()`, `edhoc_set_c509_trust_store()` |
| `os/net/security/edhoc/edhoc-cred-c509.c` | Implement chain-aware validator |
| `os/net/security/edhoc/edhoc-msgs.c` | Add time validity check in c5c parsing |
| `tests/21-security-protocols/edhoc-method0-c5t-native-{client,server}/` | **NEW** |
| `tests/21-security-protocols/edhoc-method0-c5c-native-{client,server}/` | **NEW** |
| `cooja-ng/configs/edhoc-method0-c5{t,c}-native*.json` | **NEW** |
| `os/net/app-layer/coap/mbedtls-support/mbedtls-support.c` | Type 2 DTLS path (Option A) |
