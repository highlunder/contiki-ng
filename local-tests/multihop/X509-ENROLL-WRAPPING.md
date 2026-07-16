# Wrapping the C enrollment server/CA for an X.509 (PKCS#10) enrollment trial

Investigation (task #35): how to run an **X.509 enrollment** trial in cooja by wrapping the
existing C509 enrollment C code, so it can be compared against the C509 enrollment over
multi-hop (the missing "x509 enrollment arm").

## What already exists (the enabling machinery)
The C509 service is a *lossless X.509 ↔ C509 converter*, so almost everything is present:

- **`x509_encode_full_cert(buf, size, off, const c509_cert_t *)`** — reconstructs a full
  X.509 DER certificate from a decoded C509 cert. **Already in production**: the DTLS path
  (`mbedtls-support.c:790/819/851`) uses it to hand mbedTLS X.509 DER (1024-byte buffers).
- **`c509_parse_cert(c509_cert_t *, buf, size)`** — decodes C509 cert bytes → struct (the
  input to the encoder).
- **`x509_encode_csr(buf, size, off, cbor, cbor_len)`** — reconstructs a **PKCS#10 DER
  CertificationRequest** from a C509 Type-3 CSR (`x509_encode.h:59`).
- **`c509_csr_build()` / `x509_csr_sign()`** — the enroll client already builds+self-signs a
  C509 Type-3 CSR (`edhoc-oscore-crts-client.c:355`).
- **`c509_ca_issue_cert(...)`** — the CA issuance (PoP-verified), unchanged.
- The server's `/crts` (`c509_chain_encode`) and `/sen` (bare C509 cert from the CA) handlers
  and the `/sen` idempotency cache are the only wire-format touch-points.

So the enrollment can be "dressed" in X.509 DER **at the wire boundary** while reusing the
entire CA, PoP verification, recovery, and idempotency logic. This is a wrapper, not a rewrite.

## The three flights and the three wrap points
Enrollment moves three size-relevant objects; wrap each to its X.509 DER form:

| flight | C509 now | X.509 wrap | new code |
|--------|----------|-----------|----------|
| `/crts` resp (CA chain, downlink) | `c509_chain_encode` (~135 B) | `c509_parse_cert`(CA)→`x509_encode_full_cert` (~384 B/cert) | none |
| `/sen` req (CSR, uplink) | C509 Type-3 CSR (~150 B) | client `x509_encode_csr`→PKCS#10 DER (~380 B) | server parse (see below) |
| `/sen` resp (issued cert, downlink) | bare C509 cert (~144 B) | `c509_parse_cert`→`x509_encode_full_cert` (~384 B) | none |

The two **downlink** flights (CA chain, issued cert) — the ones the client must reassemble
across the hops, i.e. the multi-hop-relevant ones — need **zero new code**: swap the response
encoder for the already-proven `x509_encode_full_cert`.

## The one gap: server-side PKCS#10 CSR parse
The server currently parses the *C509* CSR (`c509_csr_parse`); there is no PKCS#10 parser (the
DER→C509 direction is the offline Rust tool's job). Two ways to close it:

1. **Reuse mbedTLS (recommended).** mbedTLS is already linked for DTLS. `mbedtls_x509_csr_parse_der()`
   yields the subject name + `SubjectPublicKeyInfo` and verifies the PoP self-signature; hand
   the extracted subject/pubkey to `c509_ca_issue_cert()`. ~one call + field marshalling, no new
   ASN.1 code. (Enrollment apps already build with mbedTLS in the DTLS scenarios.)
2. **Minimal-gap trial (zero new code).** Keep the C509 CSR on the *uplink* but return X.509
   DER on both *downlinks*. This makes the two big reassembled-over-multi-hop flights X.509-sized
   (the dominant stress) while the compact CSR upload is a documented approximation. Good enough
   to answer "does X.509-sized enrollment degrade over hops like the x5c handshake?".

## Wrapping recipe (compile-time `ENROLL_X509=1`)
- **Server** (`edhoc-oscore-crts-server.c`): under `ENROLL_X509`, in `/crts` build the response
  as `c509_parse_cert(ca_cert)` → `x509_encode_full_cert`; in `/sen`, after `c509_ca_issue_cert`,
  `c509_parse_cert` → `x509_encode_full_cert` before responding (and cache the DER for idempotency).
  Enlarge `resp_payload` 256→640 B and raise `COAP_MAX_CHUNK_SIZE`/`EDHOC_CONF_MAX_BUFFER` as the
  x5c handshake client does. For full-faithful, add the mbedTLS PKCS#10 parse to `/sen`.
- **Client** (`edhoc-oscore-crts-client.c`): under `ENROLL_X509`, verify the returned X.509 DER
  cert (mbedTLS `mbedtls_x509_crt_parse_der` or the existing signature check over the TBS); for
  full-faithful, `x509_encode_csr` the built C509 CSR to PKCS#10 before POST. Same larger buffers.
- Reuse the existing configs pattern: `emul-enroll-x509-{1,2}hop-tsch.json`, built
  `ENROLL_X509=1 MULTIHOP_CONNECT_DELAY_S=30`.

## Expected result (why the trial is worth running)
X.509 enrollment inflates all three flights ~2.5–3×. Over multi-hop on the minimal schedule
this should degrade like the `x5chain` handshake (§ MULTIHOP-M1): the bigger CA-chain and
issued-cert reassembly should fail or need heavy recovery at 2 hops where the compact C509
enrollment completes (3/3, §C) — quantifying "credential size compounds with workload length"
on the enrollment path directly. On CSMA it should complete but slower (per §B).

## Effort
- Minimal-gap trial: ~an afternoon (response-encoder swap + buffer sizes + 2 configs), zero new
  parsing. Recommended first step.
- Full-faithful (PKCS#10 uplink + mbedTLS parse): ~small additional, reusing mbedTLS.

## Implemented (minimal-gap) + result
The **minimal-gap** version is implemented and run (`ENROLL_X509=1`). Rather than dynamically
reconstructing (which needs the c509/os-lib `cbor.o` collision resolved), the server returns the
X.509 DER equivalents of the C509 native test certs (`edhoc-cred-x509-native-test.h`: 339 B CA
cert on `/crts`, 364 B issued cert on `/sen`) — the C509 CA issuance + PoP verification still run,
only the two downlink flights' wire format changes. The client validates full DER-SEQUENCE
completeness (whole flight reassembled). Files: `edhoc-oscore-crts-{server,client}` (`ENROLL_X509`
gates + larger buffers), configs `emul-enroll-x509-{1,2}hop-tsch.json`.

Result (MULTIHOP-DTLS-CSMA-ENROLL-RESULTS.md §C.1): **1-hop 3/3 @2.9 s; 2-hop 0/3** — the 339 B
`/crts` flight never reassembles over two hops, whereas the compact C509 enrollment completes 3/3.
The enrollment analogue of the `x5chain`-handshake result, and sharper (two big flights).

## Implemented (fully-dynamic downlinks) + result

The **fully-dynamic** downlink wrapper is now implemented and run (`ENROLL_X509_DYN=1`). Both
`/crts` (CA chain) and `/sen` (issued cert) responses are reconstructed to X.509 DER **at
runtime** with `x509_encode_full_cert()` — the same lossless converter the DTLS path uses —
instead of shipping static blobs. This exercises the C509→X.509 encoder end-to-end on the
enrollment path (not just DTLS).

Two blockers were resolved:
1. **`cbor.o` object collision** — the c509 decoder `os/services/c509/cbor.c` was renamed
   `c509-cbor.c` (header `cbor.h` kept), so its object no longer collides with `os/lib/cbor.o`
   (EDHOC's CBOR writer) and both link together.
2. **`cbor_major_type_t` *header* collision** — `os/lib/cbor.h` (named enum) vs the c509
   `cbor.h` (anonymous enum typedef) still clash if both are included in one TU. Solved with a
   cbor-free shim `os/services/c509/c509-x509-wrap.{c,h}` exposing
   `c509_to_x509_der(c509, len, out, size, *out_len)`; it keeps all c509/cbor headers inside its
   own `.c`, and copies the input internally so it is safe for the `/sen` in-place
   parse→re-encode. The server TU includes only the shim header.
3. `x509_encode.c`'s two EC point-decompression sites (full-cert + CSR encoder) were gated
   `C509_X509_ENCODE_UECC` → micro-ecc `uECC_decompress` (secp256r1) for the enroll apps, which
   link uECC not mbedTLS; the default `#else` mbedTLS branch (07-c509 / DTLS) is unchanged and
   still builds clean.

Files: `edhoc-oscore-crts-server.c` (`ENROLL_X509_DYN` gates → `c509_to_x509_der`), Makefile
(`-DENROLL_X509_DYN=1 -DC509_X509_ENCODE_UECC=1`, adds `c509-x509-wrap.c x509_encode.c c509.c
c509-cbor.c der.c validity.c`), new `os/services/c509/c509-x509-wrap.{c,h}`. Configs
`emul-enroll-x509-dyn-{1,2}hop-tsch.json`, firmware `fw/enroll-x509-dyn-server.nrf` (paired with
the same `enroll-x509-client-mh.nrf`).

Result (cooja-ng-ge, seed 1, sw uECC P-256):

| hops | `/crts` DER | `/sen` DER | outcome |
|------|-------------|-----------|---------|
| **1** | 289 B (runtime) | 288 B (runtime, from 144 B C509) | **PASS @ ~48.2 s** (both flights received complete) |
| **2** | 289 B (runtime) | — | **FAIL (timeout)** — EDHOC finishes @72.2 s, server reconstructs+retransmits the 289 B CA cert, but the client never reassembles the `/crts` flight over two hops |

This **reproduces the static-blob arm's headline** (1-hop 3/3, 2-hop 0/3): the X.509-sized
downlink fails to reassemble at 2 hops where the compact C509 enrollment completes 3/3. Notably
the runtime-reconstructed DER (289 B) is *smaller* than the static blob (339 B) yet still fails —
the failure is structural (X.509-sized flight over the minimal multi-hop schedule), independent of
whether the DER is static or reconstructed.

_Status: fully-dynamic downlink wrapper implemented + run (1-hop PASS, 2-hop FAIL, matching the
static arm). Remaining full-faithfulness item (out of scope of this result): a PKCS#10 **uplink**
CSR (client `x509_encode_csr` + server `mbedtls_x509_csr_parse_der`); the two downlinks — the
multi-hop-relevant reassembled flights — are now fully dynamic._

### The earlier deferral (now closed)
The remaining step to the *fully-faithful, dynamic* wrapper (issue → `x509_encode_full_cert`;
client PKCS#10 via `x509_encode_csr` + server `mbedtls_x509_csr_parse_der`) was the c509/os-lib
`cbor.o` collision resolution. The downlink half of that (the reassembled, multi-hop-relevant
flights) is now done; only the PKCS#10 uplink remains.
