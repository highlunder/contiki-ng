# EDHOC + C509: Next Steps Plan

**Created:** 2026-06-03  
**Updated:** 2026-06-03  
**Branch:** edhoc-merge

Current state (2026-06-03): **Steps 1–3a and Method 2 KID COMPLETE, nRF52840 all PASS.**
All three credential types (KID, c5t, c5c) run EDHOC then derive an OSCORE
context and exchange a protected CoAP GET/2.05-Content in cooja-ng at ~11 s
simulated time on nRF52840-DK + native server.
Step 2 (cert validation hook), Step 3a (EAD API), and Method 2 KID (Step 4 partial) are complete.
Next: Method 2 with c5t/c5c credentials, Method 1, Step 5 (interop), or Step 6 (energy profiling).

---

## Step 1 — OSCORE context: store, derive, and protect a CoAP message

**Goal:** Turn EDHOC's key output into an actual secure CoAP channel. Currently
`edhoc_exporter_oscore()` derives Master Secret + Master Salt and prints them.
No OSCORE stack exists anywhere in the repo. This step builds the minimum OSCORE
object security layer (RFC 8613) needed to encrypt and decrypt one CoAP exchange.

### 1a — Fix CID representation in oscore_ctx_t and edhoc-exporter.c ✅ DONE

The current `oscore_ctx_t` stores sender/recipient IDs as `int`, supporting only
single-byte CIDs. RFC 8613 allows up to 7-byte IDs; RFC 9528 generates CIDs that
may be multi-byte.

- [x] In `edhoc-exporter.h`: replace `int client_ID; int server_ID;` with
  `uint8_t sender_id[EDHOC_MAX_CID_LEN]; uint8_t sender_id_len;`
  and `uint8_t recipient_id[EDHOC_MAX_CID_LEN]; uint8_t recipient_id_len;`
  (Initiator's own CID → sender; Responder's CID → recipient)
- [x] In `edhoc-exporter.c`: replace the `cid_len == 1` branch with a
  `memcpy` of the full CID bytes and set the length field
- [x] Update `print_oscore_ctx()` to print the byte arrays instead of `%02x` int
- [x] Verify all callers (test apps) still compile; update field references

### 1b — New module: os/net/security/oscore/ ✅ DONE

No OSCORE directory exists. Create the module.

- [x] Create `os/net/security/oscore/Makefile.oscore`
  — adds `os/net/security/oscore` to `MODULES`
- [x] Create `os/net/security/oscore/oscore.h` — public API (see 1c, 1d)
- [x] Create `os/net/security/oscore/oscore.c` — implementation

### 1c — OSCORE context store (RFC 8613 §3.2) ✅ DONE (single-session)

RFC 8613 defines a Security Context with Sender Context (key, seq num) and
Recipient Context (key, replay window). The context store holds one entry per
EDHOC session.

- [x] Define `oscore_security_context_t`:
  - Sender ID (up to 8 B + len), Recipient ID (up to 8 B + len)
  - Common IV (13 B) — precomputed from HKDF
  - Sender Key (16 B), Sender Sequence Number (uint64_t)
  - Recipient Key (16 B)
- [x] `oscore_derive_context(oscore_security_context_t *ctx, const oscore_ctx_t *edhoc_out)`
  — takes EDHOC exporter output, runs HKDF to fill Sender Key, Recipient Key,
  Common IV (RFC 8613 §3.2.1)
- [ ] MEMB-based store for `OSCORE_MAX_CONTEXTS` (default 2) contexts — deferred to 1f/Step 7
- [ ] `oscore_ctx_find_by_kid(const uint8_t *kid, uint8_t kid_len)` — deferred to 1f/Step 7
- [ ] Recipient replay window (uint64_t bitmask) — deferred; single-session test doesn't need it

### 1d — OSCORE object security: encrypt/decrypt (RFC 8613 §8.1–8.4) ✅ DONE

Implementation uses `cose_encrypt0_seal/open()` from the existing COSE module
(wraps CCM* driver + COSE Enc_structure) rather than raw Mbed TLS calls.

- [x] `oscore_protect_request()`: encode PIV, write OSCORE option [flag|n][piv][kid],
  build external_aad, build nonce, AES-128-CCM-8 encrypt, increment sender_seq
- [x] `oscore_unprotect_request()`: parse option flags (n, k), extract PIV+KID,
  build external_aad + nonce, AES-128-CCM-8 decrypt with recipient_key
- [x] `oscore_protect_response()`: nonce derived from request_kid + request_piv;
  response OSCORE option is empty (caller writes 0x00 byte)
- [x] `oscore_unprotect_response()`: same nonce as protect_response; decrypt with
  recipient_key (= server's sender key from client's perspective)
- [ ] Anti-replay window — deferred (single-session test, no replay risk)

### 1e — End-to-end test: EDHOC → OSCORE → CoAP GET ✅ CODE COMPLETE, AWAITING SIM RUN

New test app pair in `tests/21-security-protocols/`:

- [x] `edhoc-oscore-client/` — runs EDHOC (Method 0, KID auth, RFC 9529 static-DH
  creds), derives OSCORE context, waits 500 ms, sends OSCORE-protected CoAP GET
  on UDP port 5686; verifies 2.05 Content response
- [x] `edhoc-oscore-server/` — accepts EDHOC handshake (IS_NETWORK_ROUTING_ROOT),
  derives OSCORE context on SERV_HANDSHAKE_COMPLETE, receives OSCORE GET,
  decrypts, sends OSCORE-protected 2.05 Content "hello"
- [x] Cooja-ng JSON config: `cooja-ng/configs/edhoc-oscore.json` (TIMEOUT 120s)
  — success when client logs "EDHOC+OSCORE end-to-end test PASSED" AND
  server logs "EDHOC+OSCORE server exchange complete" with no ERR lines
- [x] Both apps build warning-free for TARGET=native and TARGET=cooja
- [x] Simulation PASS in cooja-ng (2026-06-03, 20.7 s simulated):
      - Server: OSCORE context ready, received GET code=0x01
      - Client: OSCORE response code=0x45 payload="hello"
      - No ERR messages; JS script confirmed testOK

### 1f — c5t and c5c variants of the OSCORE test ✅ DONE

- [x] Repeat 1e with `EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T`
      PASS 2026-06-03: cooja-ng native, 20.6 s, "EDHOC+OSCORE c5t end-to-end test PASSED"
      Apps: `edhoc-oscore-c5t-client/`, `edhoc-oscore-c5t-server/`
      Config: `cooja-ng/configs/edhoc-oscore-c5t.json`
- [x] Repeat 1e with `EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C`
      PASS 2026-06-03: cooja-ng native, 20.7 s, "EDHOC+OSCORE c5c end-to-end test PASSED"
      Apps: `edhoc-oscore-c5c-client/`, `edhoc-oscore-c5c-server/`
      Config: `cooja-ng/configs/edhoc-oscore-c5c.json`
- [x] Add nRF52840 cooja-ng configs for all three variants (KID, c5t, c5c)
      PASS 2026-06-03 (~11 s simulated, nRF52840-DK + native server):
      - KID:  configs/edhoc-oscore-nrf52840.json      — 11.3 s
      - c5t:  configs/edhoc-oscore-c5t-nrf52840.json  — 11.2 s
      - c5c:  configs/edhoc-oscore-c5c-nrf52840.json  — 11.8 s
      Root cause of initial KID failure and fix: see "nRF52840 timing" section below.

---

## nRF52840 timing configuration — emulated vs real hardware

The following defines appear in the client `project-conf.h` files and the
client `Makefile`.  They are all required for the emulated nRF52840 tests and
most are also appropriate (or safe) for real hardware deployment.

### COAP_RESPONSE_TIMEOUT (Makefile, default 3 s → set to 15 s)

The SEQUENCE_ERROR path sends a second MSG_1 before MSG_2 arrives, and
802.15.4 fragmentation of MSG_2 takes additional time.  The default 3 s
CoAP CON retransmit timeout is too short in both emulated and real scenarios.

- **Emulator:** required; without it, the CoAP layer retransmits MSG_1 before
  MSG_2 is received, creating spurious SEQUENCE_ERROR loops.
- **Real HW:** keep 15 s for robustness; 5–8 s would suffice on a clean link.

### EDHOC_CONF_TIMEOUT (project-conf.h, 100 000 ms = 100 s)

Session-level watchdog timer, started when the EDHOC client sends MSG_1.

- **Emulator:** timer counts simulated time; full exchange completes in ~11 s
  simulated, so 100 s is very generous.
- **Real HW:** P256 ECDH on nRF52840 takes ~300 ms; full handshake ≤ 5 s real
  time; 100 s is still very conservative.  Reduce to ~30 s if faster failure
  detection is required on production hardware.

### LPM_CONF_MAX_PM 1 (project-conf.h)

Limits nRF52840 power management to PM1 (light sleep), keeping the radio
able to wake quickly.

- **Real HW:** required.  Without it, the node can enter PM2+ deep sleep
  during ECDH computation and miss incoming frames from the border router.
- **Emulator:** the emulator does not model power states; setting it is harmless
  and keeps both environments consistent.

### RPL_MRHOF_CONF_MAX_LINK_METRIC 16384 (project-conf.h, default 512 = ETX 4)

Maximum single-hop ETX threshold above which a neighbor is rejected as a
preferred RPL parent.  ETX 128 (value 16 384 with the ×128 divisor).

- **Emulator (required):** The nRF52840 emulation produces a transient burst of
  8 MAC NACKs on the first MSG_1 transmission due to radio-alignment timing.
  Each NOACK call to `link_stats_packet_sent()` adds `ETX_NOACK_PENALTY = 12`
  extra retransmissions, raising the EWMA ETX to ~832 (6.5× the default
  threshold).  `rpl_link_callback()` then schedules a deferred
  `rpl_dag_update_state()` via a 0-delay ctimer; when it fires, MRHOF rejects
  the parent (`nbr_is_acceptable_parent()` = false), `dag.state` drops to
  `DAG_INITIALIZED`, and `node_is_reachable()` returns 0.  The next
  `coap_sendto()` call for MSG_3 is silently dropped by
  `coap_endpoint_is_connected()` with a WARN log but no retry.
- **Real HW:** not needed on a clean 802.15.4 link (typical ETX 1–2); safe to
  keep as a defensive measure against transient link degradation.

### RPL_MRHOF_CONF_MAX_PATH_COST 32768 (project-conf.h)

Path-cost threshold (sum of all hop ETX values along the DAG path).  Paired
with `MAX_LINK_METRIC`; keep at 32 768 whenever `MAX_LINK_METRIC` is raised.

### RPL_CONF_PARENT_TIMEOUT 30 (project-conf.h)

**No-op.**  This symbol is defined in these project-conf files but is not
referenced anywhere in the RPL Lite OS sources (`os/net/routing/rpl-lite/`).
It has no runtime effect.  It is retained here as documentation of what was
attempted; remove it if it causes confusion.

---

## Step 2 — Certificate validation hook (B5) ✅ DONE

**Goal:** Make c5c safe for open deployments. Currently any inline cert is accepted
without checking the issuer signature or validity period.

- [x] Add `edhoc_cert_validator_fn` typedef + `cert_validator`/`cert_validator_ctx`
  fields to `edhoc_config_t` in `edhoc.h`
- [x] Call the hook in `edhoc_authenticate_msg()` in `edhoc.c` after
  `edhoc_get_key_id_cred_x()` when `key->c509_data != NULL`.
  Returns `EDHOC_ERR_CERTIFICATE_REJECTED` (-35) if hook returns non-zero.
- [x] Default: NULL = trust-on-first-use (no regression for KID/c5t/unregistered apps)
- [x] `edhoc_set_cert_validator(fn, app_ctx)` — can be called before `edhoc_client_run()`
  (stored as a pending validator, copied into context by `edhoc_new()`)
- [x] Sample validator `edhoc_c509_validate_self_signed()` in `edhoc-cred-c509.c`:
  - Type 0/1/3 (DER-equivalent): structural check only (pk extraction)
  - Type 2 (native C509): full ECDSA-P-256 over SHA-256(CBOR TBS) verified with `ecc_verify_hash()`
- [x] Both c5c test apps register `edhoc_c509_validate_self_signed`
- [x] cooja-ng PASS 2026-06-03: 20.7 s; both nodes log "type-3 (DER-equiv) — structural check OK"
  and "Peer certificate accepted by validator" before the OSCORE exchange completes

---

## Step 3 — EAD application handler API

**Goal:** Allow applications to implement EAD label handlers without forking the
core, and lay the groundwork for LAKE-authz (device onboarding vouchers).

### 3a — Handler registration API ✅ DONE 2026-06-03

- [x] In `edhoc-msgs.c`: replace the `TODO` stub with a registration table
  (`ead_handlers[EDHOC_EAD_MAX_HANDLERS]`, configurable via `EDHOC_CONF_EAD_MAX_HANDLERS`)
- [x] Add `edhoc_ead_handler_fn` typedef and `edhoc_register_ead_handler()` to `edhoc-msgs.h`
  — update-in-place for existing labels; NULL removes; full → `EDHOC_ERR_BUFFER_OVERFLOW`
- [x] Call registered handlers from `edhoc_process_ead_item()` before falling
  through to the critical/non-critical default (exact label match including sign)
- [x] Non-critical unknown items: continue silently (no change)
- [x] Critical unknown items: return `EDHOC_ERR_CRITICAL_EAD_UNSUPPORTED` (no change)
- [x] `edhoc.h`: add usage documentation cross-referencing `edhoc-msgs.h`

### 3b — LAKE-authz EAD handler (draft-ietf-lake-edhoc-authz)

LAKE-authz uses EAD_1 (label = TBD, currently -1 in draft) to carry a voucher
from an Enrollment Server, enabling zero-touch device onboarding without
pre-provisioned peer credentials.

- [ ] Read draft-ietf-lake-edhoc-authz-latest; extract EAD label values
- [ ] Implement EAD_1 voucher parsing: CBOR-decode the voucher structure, extract
  the trust anchor cert hash and signature
- [ ] Implement EAD_2 / EAD_3 response path (Enrollment Server voucher exchange)
- [ ] Test: simulated Enrollment Server (native) ↔ constrained client (cooja)
  — client has no pre-provisioned credential; receives voucher in EAD_1

---

## Step 4 — Method 1 and 2 testing with C509 credentials

**Goal:** Validate the asymmetric EDHOC methods with C509 credentials (the code
compiles but no test exercises these paths).

### 4a — Method 2 KID baseline ✅ DONE 2026-06-03

Method 2 = I:StaticDH | R:Sig. Client uses static DH key (no ECDSA), server
signs MAC_2 with ECDSA P-256.  Same P-256 key material for both, different code
paths selected at compile time via EDHOC_CONF_METHOD.

- [x] Apps: `tests/21-security-protocols/edhoc-method2-kid-client/`,
  `edhoc-method2-kid-server/`
- [x] Credentials: RFC 9529 static DH keys (P-256), KID=0x2b (client), KID=0x32 (server)
- [x] Config: `cooja-ng/configs/edhoc-method2-kid.json`
- [x] PASS 2026-06-03: 20.646 s simulated, both nodes derive same OSCORE Master
  Secret (`e6dbd175ec3969303d0ca36be561571f`), GET/Content OSCORE exchange OK

### 4b — Method 2 with c5t/c5c credentials

Use C509 test certificates with `EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T`
or `EDHOC_CRED_C509_C5C` for the same Method 2 flow (server signs).

- [ ] `edhoc-method2-c5t-client/`, `edhoc-method2-c5t-server/` + config
- [ ] `edhoc-method2-c5c-client/`, `edhoc-method2-c5c-server/` + config

### 4c — Method 1 (Sig|StaticDH)

Method 1 = I:Sig | R:StaticDH. Client signs; server uses static DH.

- [ ] `edhoc-method1-kid-client/`, `edhoc-method1-kid-server/` + config
- [ ] c5t variant

### 4d — nRF52840 emulation

- [ ] Run Method 2 KID on nRF52840-DK cooja-ng config (add RPL tuning to
  client project-conf.h as in KID/c5t/c5c OSCORE tests)

---

## Step 5 — Interoperability measurement

**Goal:** Confirm the wire encoding of c5t and c5c credential exchange is
spec-correct against an independent EDHOC implementation.

- [ ] Identify a peer EDHOC implementation with C509 support
  (options: Python `edhoc` library, Java RISE implementation, or the Rust
  `CBOR-certificates/c509_demo_impl` extended with an EDHOC layer)
- [ ] Run Contiki-NG (native) as Initiator against the peer Responder with:
  - Method 0, c5t credential — compare transcript hashes and OSCORE output
  - Method 0, c5c credential — same
- [ ] Document any wire-encoding divergences from RFC 9528 / C509 draft
- [ ] If divergences found: fix in `edhoc-cred-c509.c` and re-run

---

## Step 6 — Energy and performance profiling

**Goal:** Produce the resource-constrained evaluation data for publication.
Comparisons: KID vs c5t vs c5c; DTLS vs EDHOC+OSCORE.

- [ ] Hardware: nRF52840 DK + Nordic Power Profiler Kit 2 (PPK2)
- [ ] Metrics per handshake type:
  - Wall-clock time (Renode simulated time as proxy; real-HW for publication)
  - Peak current draw and total charge (µC per handshake) on real hardware
  - Flash footprint (text size from `arm-none-eabi-size`)
  - RAM footprint (data + bss + measured peak stack from Step C4)
- [ ] Test matrix:
  - EDHOC Method 0: KID, c5t, c5c (all on nRF52840 DK)
  - DTLS 1.2 baseline (existing `c509-dtls-*.json` configs)
- [ ] Tabulate results; compute overhead ratios (c5t/c5c vs KID baseline)
- [ ] (Optional) per-phase breakdown: MSG_1, MSG_2, MSG_3 timing from logs

---

## Step 7 — LwM2M bootstrap with EDHOC+OSCORE

**Goal:** Use EDHOC+OSCORE as the LwM2M 1.2 bootstrap security mode in
place of DTLS. LwM2M 1.2 (OMA-TS-LightweightM2M_Core-V1_2) defines OSCORE
as a mandatory security mode.

**Note:** Step 1 (OSCORE stack) is a hard prerequisite.

- [ ] Identify the Contiki-NG LwM2M implementation location
  (`examples/lwm2m-ipso-objects/` and `os/net/app-layer/lwm2m/`)
- [ ] Map LwM2M security object (Object 0) fields to EDHOC credential parameters
- [ ] Replace DTLS context setup in LwM2M bootstrap with EDHOC handshake +
  OSCORE context derivation
- [ ] Test: LwM2M client (nRF52840) bootstraps from a LwM2M server (native)
  using EDHOC with c5t credentials; registers Objects 1, 3, 4 over OSCORE
- [ ] Compare registration time and message count vs DTLS bootstrap

---

## Priority order and dependencies

```
Step 1 (OSCORE) ──┬── Step 1f (c5t/c5c OSCORE variants)
                  ├── Step 6 (energy profiling — OSCORE baseline needed)
                  └── Step 7 (LwM2M — needs OSCORE stack)

Step 2 (cert validation) ── standalone, can run in parallel with Step 1

Step 3 (EAD API) ──── Step 3b (LAKE-authz) ── standalone

Step 4 (Methods 1/2) ── standalone, can run in parallel

Step 5 (interop) ── can run after Step 1 (needs a working OSCORE exchange to compare)
```

| Step | Effort | Value | Hard deps |
|------|--------|-------|-----------|
| 1. OSCORE | High | Very high | — |
| 2. Cert validation | Low | High | — |
| 3. EAD API | Medium | High | — |
| 4. Method 1/2 | Low | Medium | — |
| 5. Interop | Medium | High | Step 1 helpful |
| 6. Energy profiling | Medium | Very high | Step 1 |
| 7. LwM2M | High | High | Step 1 |

---

## Implementation order within Step 1

Step 1 is the most complex and requires careful ordering:

1. **1a** — Fix CID types (edhoc-exporter.h/.c). Small, isolated, no new files.
2. **1b+1c** — Create oscore/ module with context store and HKDF derivation.
3. **1d** — Encrypt/decrypt using Mbed TLS AES-CCM. Needs Mbed TLS available
   (already in the repo for DTLS; use `mbedtls_ccm_*` from `library/ccm.c`).
4. **1e** — End-to-end test with KID credentials.
5. **1f** — Repeat test with c5t and c5c credentials.
