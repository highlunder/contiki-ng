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
 *   Minimal PKCS#10 (RFC 2986) CertificationRequest DER parser for the CA's
 *   /sen endpoint. Extracts exactly the three fields the C509 CA issuance
 *   needs — the subject commonName, the secp256r1 public key, and the signed
 *   CertificationRequestInfo (CRI) + its raw r||s signature — so the parsed
 *   result can be fed straight to c509_csr_verify_pop() and
 *   c509_ca_issue_cert().
 *
 *   The inverse of x509_encode_csr(): parses only the shape that encoder
 *   produces — a single-CN subject Name, a secp256r1 uncompressed
 *   SubjectPublicKeyInfo, and an ecdsa-with-SHA256 signature. It is not a
 *   general X.509/PKCS#10 parser.
 *
 *   Self-contained: only stdint/stddef, no ASN.1 library and (unlike
 *   x509_encode.c) no mbedTLS or c509/cbor.h dependency — so it links into
 *   the EDHOC/OSCORE enrollment server without the os/lib/cbor.h
 *   `cbor_major_type_t` collision, same rationale as c509-csr-parse.h/.c.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef X509_CSR_PARSE_H
#define X509_CSR_PARSE_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Parses a PKCS#10 DER CertificationRequest (secp256r1, single-CN).
 *
 * All `out`-pointers point into \p buf (nothing is copied) except \p sig_rs,
 * which the caller supplies as a 64-byte buffer to receive the fixed-width
 * `r||s` signature (each INTEGER left-zero-padded to 32 bytes) — the form
 * c509_csr_verify_pop()/uECC_verify() expect.
 *
 * \param buf          CertificationRequest DER bytes.
 * \param len          Length of \p buf.
 * \param subject      Out: pointer to the subject commonName string bytes.
 * \param subject_len  Out: length of the commonName.
 * \param pk_key       Out: pointer to the 65-byte uncompressed EC point
 *                       (`0x04 || X || Y`) inside the SubjectPublicKeyInfo.
 * \param pk_key_len   Out: length of \p pk_key (65 on success).
 * \param cri_ptr      Out: pointer to the CertificationRequestInfo TLV (the
 *                       signed bytes), suitable as c509_csr_verify_pop()'s
 *                       tbs_ptr.
 * \param cri_len      Out: length of the CertificationRequestInfo TLV.
 * \param sig_rs       Out: caller-supplied 64-byte buffer, filled with the
 *                       fixed-width `r||s` signature.
 * \return 0 on success, -1 on malformed/truncated input or a shape this
 *         parser does not support.
 */
int x509_csr_parse(const uint8_t *buf, size_t len,
                   const uint8_t **subject, size_t *subject_len,
                   const uint8_t **pk_key, size_t *pk_key_len,
                   const uint8_t **cri_ptr, size_t *cri_len,
                   uint8_t *sig_rs);

#endif /* X509_CSR_PARSE_H */
