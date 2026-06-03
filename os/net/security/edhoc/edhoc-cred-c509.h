/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB
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
 *   C509 certificate credential support for EDHOC.
 *
 *   Implements the two C509 credential modes defined in RFC 9528 §3.5.2 and
 *   draft-ietf-cose-cbor-encoded-cert:
 *
 *   - c5t  (COSE header 22): hash-by-reference.  ID_CRED_x = {22: [-15, h'8b]}
 *     CRED_x = raw C509 bytes.  Both parties pre-provision the peer cert.
 *
 *   - c5c  (COSE header 25): by-value.  ID_CRED_x = {25: h'cert'}.
 *     CRED_x = raw C509 bytes.  Cert delivered inline; no pre-provisioning.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef EDHOC_CRED_C509_H_
#define EDHOC_CRED_C509_H_

#include <stddef.h>
#include <stdint.h>
#include "edhoc-error.h"
#include "edhoc-key-storage.h"

/**
 * \brief Copy raw C509 bytes into the CRED_x output buffer.
 *
 * \param key     Key storage entry; must have c509_data and c509_len set.
 * \param out     Output buffer for CRED_x.
 * \param out_sz  Size of output buffer.
 * \return        Number of bytes written, or 0 on error.
 *
 * Per RFC 9528 §3.5.2: when the authentication credential is a C509
 * certificate, CRED_x SHALL be the C509 certificate bytes.
 */
size_t edhoc_c509_generate_cred_x(const cose_key_t *key,
                                   uint8_t *out, size_t out_sz);

/**
 * \brief Build ID_CRED_x for c5t mode: {22: [-15, h'<8-byte hash>']}.
 *
 * \param key     Key storage entry with c509_data/c509_len.
 * \param out     Output buffer.
 * \param out_sz  Size of output buffer.
 * \return        Number of bytes written, or 0 on error.
 *
 * Uses SHA-256 truncated to EDHOC_C5T_HASH_LEN (8) bytes per RFC 9528 §9.3.
 */
size_t edhoc_c509_generate_id_cred_c5t(const cose_key_t *key,
                                        uint8_t *out, size_t out_sz);

/**
 * \brief Build ID_CRED_x for c5c mode: {25: h'<C509 bytes>'}.
 *
 * \param key     Key storage entry with c509_data/c509_len.
 * \param out     Output buffer.
 * \param out_sz  Size of output buffer.
 * \return        Number of bytes written, or 0 on error.
 */
size_t edhoc_c509_generate_id_cred_c5c(const cose_key_t *key,
                                        uint8_t *out, size_t out_sz);

/**
 * \brief Compute SHA-256/64 (8-byte truncated hash) of a C509 certificate.
 *
 * \param c509          C509 certificate bytes.
 * \param c509_len      Length of certificate.
 * \param hash_out      Output buffer; must be at least hash_trunc_len bytes.
 * \param hash_trunc_len Number of leading bytes to retain from the full digest.
 */
void edhoc_c509_hash_cert(const uint8_t *c509, size_t c509_len,
                           uint8_t *hash_out, size_t hash_trunc_len);

/**
 * \brief Extract the P-256 public key from a C509 certificate.
 *
 * Parses the C509 CBOR, reads the SubjectPublicKeyInfo, decompresses the
 * EC point (C509 uses 0xFD/0xFE prefix convention), and fills
 * key_out->ecc.pub.x and key_out->ecc.pub.y with the 32-byte coordinates.
 * Also sets key_out->kty and key_out->crv.
 *
 * \param c509     C509 certificate bytes.
 * \param c509_len Length of certificate.
 * \param key_out  cose_key_t to fill with the extracted public key.
 * \return EDHOC_SUCCESS, or a negative error code.
 *
 * \note Only P-256 (secp256r1) is supported; other curves return error.
 */
edhoc_error_t edhoc_c509_extract_pub_key(const uint8_t *c509, size_t c509_len,
                                          cose_key_t *key_out);

/**
 * \brief Find a key store entry whose C509 cert hashes to the given value.
 *
 * \param hash      Truncated hash bytes to match.
 * \param hash_len  Number of hash bytes to compare.
 * \param key_out   Set to the matching cose_key_t on success.
 * \return EDHOC_SUCCESS if found, EDHOC_ERR_KEY_NOT_FOUND otherwise.
 */
edhoc_error_t edhoc_c509_lookup_by_hash(const uint8_t *hash, size_t hash_len,
                                         cose_key_t **key_out);

/**
 * \brief Sample edhoc_cert_validator_fn for self-signed C509 certificates.
 *
 * Validates that the peer's inline C509 certificate is structurally sound and,
 * where possible, that the signature is self-consistent:
 *
 * - **Type 0, 1, 3** (DER-equivalent / reconstructed from X.509 DER): only a
 *   structural check is performed (public key extraction must succeed).
 *   Full ECDSA verification would require reconstructing the DER
 *   TBSCertificate, which is out of scope for this implementation.
 *
 * - **Type 2** (natively signed C509): SHA-256(CBOR TBS fields 0-9) is
 *   computed and the ECDSA-P-256 signature in field 10 is verified against
 *   the public key in field 8.
 *
 * Suitable as a quick sanity check for test deployments and as a template
 * for application-specific validators.  Not a full PKI chain check.
 * app_ctx is ignored.
 *
 * \return EDHOC_SUCCESS if the cert is valid,
 *         EDHOC_ERR_CERTIFICATE_REJECTED otherwise.
 */
edhoc_error_t edhoc_c509_validate_self_signed(const uint8_t *c509,
                                               size_t c509_len,
                                               void *app_ctx);

#endif /* EDHOC_CRED_C509_H_ */
