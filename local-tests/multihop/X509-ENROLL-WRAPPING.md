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

The remaining step to the *fully-faithful, dynamic* wrapper (issue → `x509_encode_full_cert`;
client PKCS#10 via `x509_encode_csr` + server `mbedtls_x509_csr_parse_der`) is the c509/os-lib
`cbor.o` collision resolution — the only real work, and orthogonal to the multi-hop result above.

_Status: minimal-gap implemented + run; fully-dynamic wrapper deferred on the cbor.o collision._
