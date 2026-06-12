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
 *   Builds and self-signs a C509 Type-3 CSR (CertificationRequest), per
 *   draft-ietf-cose-cbor-encoded-cert §8: a flat 7-element CBOR sequence
 *   `[type=3, sigAlg, subject, pkAlg, pkKey, attrs, sigValue]`.
 *
 *   Self-contained (no dependency on os/services/c509/cbor.h or c509.h, and
 *   thus no conflict with os/lib/cbor.h's `cbor_major_type_t`), so this
 *   module can be linked into EDHOC/OSCORE applications that already pull
 *   in the os/lib CBOR writer — same rationale as c509-chain.h/.c.
 *
 *   The resulting CSR can be fed to x509_encode_csr() (x509_encode.h) to
 *   reconstruct a PKCS#10 DER CertificationRequest.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_CSR_BUILD_H
#define C509_CSR_BUILD_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Builds a flat C509 Type-3 CSR CBOR sequence with a placeholder
 * signature.
 *
 * Writes the 7-field C509 CertificationRequest sequence (draft-ietf-cose-
 * cbor-encoded-cert §8): `[type=3, sigAlg=ecdsa-with-sha256, subject, pkAlg,
 * pkKey, attrs=[], sigValue]`. `subject` is written as a CBOR text string
 * (decoded by x509_encode_name() / the Rust reference tool as a single-RDN
 * `CN=<subject>` Name). `attrs` is written as an empty CBOR array (no
 * extensionRequest/challengePassword/PoP attributes). `sigValue` is written
 * as a 64-byte all-zero placeholder byte string, to be filled in by
 * x509_csr_sign().
 *
 * \param buffer      Output buffer.
 * \param size        Size of \p buffer in bytes.
 * \param offset      In/out byte offset within \p buffer; advanced past the
 *                     whole CSR (including the 64-byte sigValue placeholder).
 * \param subject     Subject name bytes (e.g. ASCII "my-device").
 * \param subject_len Length of \p subject in bytes.
 * \param pk_alg_id   C509 public-key algorithm ID (e.g. C509_PK_SECP256R1).
 * \param pk_key      Subject public key bytes (e.g. 65-byte uncompressed EC
 *                     point).
 * \param pk_key_len  Length of \p pk_key in bytes.
 * \param tbs_len     Out: byte offset within \p buffer marking the end of
 *                     the to-be-signed (TBS) fields (fields 0-5), i.e. the
 *                     start of the sigValue field's CBOR header. Pass to
 *                     x509_csr_sign().
 * \return 0 on success, -1 on error (buffer too small).
 */
int x509_encode_csr_build(uint8_t *buffer, size_t size, size_t *offset,
                          const uint8_t *subject, size_t subject_len,
                          int64_t pk_alg_id,
                          const uint8_t *pk_key, size_t pk_key_len,
                          size_t *tbs_len);

/**
 * \brief Signs a CSR built by x509_encode_csr_build(), filling in sigValue.
 *
 * Computes SHA-256 over `buffer[0 .. tbs_len)` (the CBOR-encoded fields
 * `[type, sigAlg, subject, pkAlg, pkKey, attrs]`) via sha_256_hash()
 * (os/lib/sha-256.c), signs the digest with uECC_sign_deterministic()
 * (RFC 6979 deterministic ECDSA, secp256r1, micro-ecc) using the supplied
 * private key, and writes the resulting `r||s` (32 bytes each) into the
 * 64-byte sigValue placeholder at the end of the buffer. No mbedTLS
 * dependency — both sha-256 and micro-ecc are already linked into EDHOC
 * apps.
 *
 * \param buffer       The CSR buffer, as produced by x509_encode_csr_build().
 * \param tbs_len      The TBS length, as returned by x509_encode_csr_build().
 * \param total_len    The total CSR length (offset returned by
 *                      x509_encode_csr_build(), including the sigValue
 *                      placeholder).
 * \param priv_key     Private key scalar `d`, big-endian (32 bytes for
 *                      secp256r1).
 * \param priv_key_len Length of \p priv_key in bytes (must be 32).
 * \return 0 on success, -1 on error (buffer too small, bad key length, or
 *         signing failure).
 */
int x509_csr_sign(uint8_t *buffer, size_t tbs_len, size_t total_len,
                  const uint8_t *priv_key, size_t priv_key_len);

#endif /* C509_CSR_BUILD_H */
