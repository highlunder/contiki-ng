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
 *   X.509 (DER) certificate credential support for EDHOC.
 *
 *   Implements the x5chain credential mode (COSE header label 33,
 *   draft-ietf-cose-x509): by-value, analogous to the C509 c5c mode but
 *   carrying a raw X.509 DER certificate instead of a CBOR-encoded one.
 *
 *   - x5chain (COSE header 33): by-value.  ID_CRED_x = {33: bstr(DER cert)}.
 *     CRED_x = raw X.509 DER bytes.  Cert delivered inline; no
 *     pre-provisioning of the peer's certificate is required.
 *
 *   This module is self-contained: it parses just enough DER (TLV walking,
 *   no general ASN.1 library) to extract the SubjectPublicKeyInfo and the
 *   TBSCertificate/signature for self-signed verification, using
 *   os/lib/sha-256.h + os/net/security/micro-ecc/uECC.h — same convention
 *   as edhoc-cred-c509.c and the c509-csr-parse.c / c509-ca.c modules.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef EDHOC_CRED_X509_H_
#define EDHOC_CRED_X509_H_

#include <stddef.h>
#include <stdint.h>
#include "edhoc-error.h"
#include "edhoc-key-storage.h"

/**
 * \brief Copy raw X.509 DER bytes into the CRED_x output buffer.
 *
 * \param key     Key storage entry; must have c509_data/c509_len set to the
 *                  DER bytes (field names reused from the C509 credential
 *                  path; they hold raw cert bytes regardless of encoding).
 * \param out     Output buffer for CRED_x.
 * \param out_sz  Size of output buffer.
 * \return        Number of bytes written, or 0 on error.
 */
size_t edhoc_x509_generate_cred_x(const cose_key_t *key,
                                   uint8_t *out, size_t out_sz);

/**
 * \brief Build ID_CRED_x for x5chain mode: {33: h'<DER cert bytes>'}.
 *
 * \param key     Key storage entry with c509_data/c509_len set to the DER
 *                  certificate bytes.
 * \param out     Output buffer.
 * \param out_sz  Size of output buffer.
 * \return        Number of bytes written, or 0 on error.
 */
size_t edhoc_x509_generate_id_cred_x5chain(const cose_key_t *key,
                                            uint8_t *out, size_t out_sz);

/**
 * \brief Extract the P-256 public key from an X.509 DER certificate.
 *
 * Walks the DER TLV structure down to SubjectPublicKeyInfo and copies the
 * 32-byte X/Y coordinates of the (uncompressed, 0x04-prefixed) EC point into
 * key_out->ecc.pub.x / key_out->ecc.pub.y.  Also sets key_out->kty and
 * key_out->crv.
 *
 * \param der      X.509 certificate, DER-encoded.
 * \param der_len  Length of \p der.
 * \param key_out  cose_key_t to fill with the extracted public key.
 * \return EDHOC_SUCCESS, or a negative error code.
 *
 * \note Only uncompressed P-256 (secp256r1) public keys are supported.
 */
edhoc_error_t edhoc_x509_extract_pub_key(const uint8_t *der, size_t der_len,
                                          cose_key_t *key_out);

/**
 * \brief Sample edhoc_cert_validator_fn for self-signed X.509 certificates.
 *
 * Parses the DER TBSCertificate and signatureValue, recomputes
 * SHA-256(TBSCertificate DER bytes), and verifies the ECDSA-P-256 signature
 * against the certificate's own embedded public key (issuer == subject).
 *
 * Suitable as a quick sanity check for test deployments and as a template
 * for application-specific validators.  Not a full PKI chain check.
 *
 * \param der      Peer's X.509 certificate bytes (as received in CRED_x).
 * \param der_len  Length of \p der in bytes.
 * \param app_ctx  Ignored.  Pass NULL.
 *
 * \return EDHOC_SUCCESS if the cert is valid,
 *         EDHOC_ERR_CERTIFICATE_REJECTED otherwise.
 */
edhoc_error_t edhoc_x509_validate_self_signed(const uint8_t *der,
                                               size_t der_len,
                                               void *app_ctx);

#endif /* EDHOC_CRED_X509_H_ */
