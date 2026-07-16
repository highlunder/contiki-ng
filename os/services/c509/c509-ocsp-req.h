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
 *   On-device C509 OCSP **request** builders (draft-liao-cose-c509-revocation,
 *   "C509 OCSP Request"). A constrained client uses these to ask a responder
 *   for certificate status:
 *   - `C509SimpleOCSPRequest` (type 2): one target cert, the most compact form —
 *     `[2, hashAlgorithm, nonce, issuerCertHash, serialNumberHash, extensions]`;
 *   - `C509UnsignedOCSPRequest` (type 0): several certs, grouped per issuer —
 *     `[0, hashAlgorithm, nonce, extensions, requests]`.
 *
 *   (`C509SignedOCSPRequest` (type 1) additionally carries a requestor signature;
 *   it is left for the signing pass, mirroring the on-device CSR path.)
 *
 *   Self-contained: stdint/stddef + a local minimal CBOR writer, no CBOR/ASN.1
 *   library and no os/services/c509/cbor.h — links into EDHOC/OSCORE/DTLS
 *   clients without the `cbor_major_type_t` collision, like the sibling
 *   revocation modules.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_OCSP_REQ_H
#define C509_OCSP_REQ_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Build a C509SimpleOCSPRequest (single target certificate).
 *
 * \param out          output buffer.
 * \param out_size     capacity of \p out.
 * \param out_len      out: bytes written.
 * \param hash_alg     hashAlgorithm id (e.g. 0 = SHA-256).
 * \param nonce        nonce bytes, or NULL for a null nonce.
 * \param nonce_len    length of \p nonce (0 with NULL).
 * \param issuer_cert_hash   issuerCertHash bytes.
 * \param issuer_hash_len    its length.
 * \param serial_number_hash serialNumberHash bytes.
 * \param serial_hash_len    its length.
 * \return 0 on success, -1 on error (buffer too small / bad args).
 */
int c509_ocsp_build_simple_request(uint8_t *out, size_t out_size, size_t *out_len,
                                   int64_t hash_alg,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *issuer_cert_hash,
                                   size_t issuer_hash_len,
                                   const uint8_t *serial_number_hash,
                                   size_t serial_hash_len);

/** One target serial (by hash) within an issuer group. */
typedef struct {
  const uint8_t *serial_number_hash;
  size_t serial_hash_len;
} c509_ocsp_single_t;

/** One issuer's group of target certificates. */
typedef struct {
  const uint8_t *issuer_cert_hash;
  size_t issuer_hash_len;
  const c509_ocsp_single_t *singles;
  size_t n_singles;
} c509_ocsp_group_t;

/**
 * \brief Build a C509UnsignedOCSPRequest (multiple certs, grouped per issuer).
 *
 * Extensions are emitted empty for every group and single request (the common
 * case); the top-level extensions are also empty.
 *
 * \param out        output buffer.
 * \param out_size   capacity of \p out.
 * \param out_len    out: bytes written.
 * \param hash_alg   hashAlgorithm id.
 * \param nonce      nonce bytes, or NULL for a null nonce.
 * \param nonce_len  length of \p nonce.
 * \param groups     per-issuer request groups.
 * \param n_groups   number of groups.
 * \return 0 on success, -1 on error.
 */
int c509_ocsp_build_unsigned_request(uint8_t *out, size_t out_size, size_t *out_len,
                                     int64_t hash_alg,
                                     const uint8_t *nonce, size_t nonce_len,
                                     const c509_ocsp_group_t *groups,
                                     size_t n_groups);

/**
 * \brief Build a signed C509SignedOCSPRequest (type 1), ECDSA-secp256r1-SHA256.
 *
 * Lays out `[1, sigAlg, hashAlg, nonce, requestorCertHash, extensions, requests,
 * requestorCerts, signatureValue]` and signs the `TBSOCSPRequest` (the CBOR
 * sequence of the first eight elements) with the requestor's secp256r1 key,
 * appending the 64-byte r||s signature. Links the ECDSA signer
 * (x509_csr_sign_msg from c509-csr-build.c) at link time.
 *
 * \param sig_alg              signatureAlgorithm id written into the request.
 * \param hash_alg             hashAlgorithm id.
 * \param nonce,nonce_len      nonce bytes, or NULL for a null nonce.
 * \param requestor_cert_hash  the requestor's cert hash (+ its length).
 * \param groups,n_groups      per-issuer request groups.
 * \param requestor_certs      requestorCerts blob, or NULL for null (+ length).
 * \param priv_key,priv_key_len requestor secp256r1 private key (32 bytes).
 * \return 0 on success, -1 on error.
 */
int c509_ocsp_build_signed_request(uint8_t *out, size_t out_size, size_t *out_len,
                                   int64_t sig_alg, int64_t hash_alg,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *requestor_cert_hash,
                                   size_t requestor_hash_len,
                                   const c509_ocsp_group_t *groups, size_t n_groups,
                                   const uint8_t *requestor_certs,
                                   size_t requestor_certs_len,
                                   const uint8_t *priv_key, size_t priv_key_len);

#endif /* C509_OCSP_REQ_H */
