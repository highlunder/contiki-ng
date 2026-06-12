/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *   CA-side issuance of a C509 Type-2 certificate (draft-ietf-cose-cbor-
 *   encoded-cert §6, "natively signed" form): given a validated CSR's
 *   (subject, pkAlg, pkKey) and the CA's identity/key, builds and signs a
 *   new flat 11-field CBOR sequence
 *   `[type=2, serialNumber, issuerSigAlg, issuer, notBefore, notAfter,
 *     subject, subjectPKAlg, subjectPK, extensions=null, sigValue]`.
 *
 *   Self-contained (no dependency on os/services/c509/cbor.h or c509.h, and
 *   thus no conflict with os/lib/cbor.h's `cbor_major_type_t`), so this
 *   module can be linked into EDHOC/OSCORE applications — same rationale as
 *   c509-chain.h/.c and c509-csr-build.h/.c.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_CA_H
#define C509_CA_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Builds and signs a new C509 Type-2 certificate for a CSR's subject.
 *
 * Writes the 10 TBS fields `[type=2, serialNumber, issuerSigAlg=ecdsa-with-
 * sha256, issuer, notBefore, notAfter, subject, subjectPKAlg, subjectPK,
 * extensions=null]`, hashes them with sha_256_hash() (os/lib/sha-256.c),
 * signs the digest with uECC_sign_deterministic() (RFC 6979, secp256r1,
 * micro-ecc) using the CA's private key, and appends the resulting `r||s`
 * as the 64-byte sigValue field. No mbedTLS dependency.
 *
 * `pk_key` is expected in 65-byte uncompressed EC point form (`0x04 || X ||
 * Y`, as produced e.g. by x509_encode_csr_build()'s CSR `pkKey` field for
 * secp256r1) and is converted to C509's 33-byte compressed form (`0xFE`/
 * `0xFD` prefix + X, per the Y-coordinate parity) for the `subjectPK` field.
 * Only secp256r1 (`C509_PK_SECP256R1`) is supported.
 *
 * \param buffer        Output buffer to receive the issued certificate.
 * \param size          Size of \p buffer in bytes.
 * \param offset        In/out byte offset within \p buffer; advanced past
 *                       the whole issued certificate (including sigValue).
 * \param serial        Certificate serialNumber bytes.
 * \param serial_len    Length of \p serial in bytes.
 * \param issuer        Issuer name bytes (CA's subject name, e.g. ASCII
 *                       "EDHOC-Test-CA").
 * \param issuer_len    Length of \p issuer in bytes.
 * \param not_before    notBefore as a Unix timestamp.
 * \param not_after     notAfter as a Unix timestamp.
 * \param subject       Subject name bytes, from the CSR.
 * \param subject_len   Length of \p subject in bytes.
 * \param pk_alg_id     C509 public-key algorithm ID from the CSR (only
 *                       C509_PK_SECP256R1 is supported).
 * \param pk_key        Subject public key, 65-byte uncompressed EC point
 *                       (`0x04 || X || Y`), from the CSR.
 * \param pk_key_len    Length of \p pk_key in bytes (must be 65).
 * \param ca_priv_key   CA private key scalar `d`, big-endian (32 bytes for
 *                       secp256r1).
 * \param ca_priv_key_len Length of \p ca_priv_key in bytes (must be 32).
 * \return 0 on success, -1 on error (buffer too small, unsupported
 *         algorithm/key length, or signing failure).
 */
int c509_ca_issue_cert(uint8_t *buffer, size_t size, size_t *offset,
                       const uint8_t *serial, size_t serial_len,
                       const uint8_t *issuer, size_t issuer_len,
                       int64_t not_before, int64_t not_after,
                       const uint8_t *subject, size_t subject_len,
                       int64_t pk_alg_id,
                       const uint8_t *pk_key, size_t pk_key_len,
                       const uint8_t *ca_priv_key, size_t ca_priv_key_len);

#endif /* C509_CA_H */
