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
 *   On-device C509 OCSP **response** parsing (draft-liao-cose-c509-revocation,
 *   "C509 OCSP Response"). Discriminates the three response types and looks up a
 *   target certificate's status by (issuerCertHash, serialNumberHash):
 *   - `C509ErrorOCSPResponse`  (type 0): `[type, responseStatus]`;
 *   - `C509BasicOCSPResponse`  (type 1): a signed multi-cert response whose
 *     `responses` array holds 3-element PerIssuer groups of 5-element
 *     SingleCertResponse entries;
 *   - `C509SimpleOCSPResponse` (type 2): a signed single-cert response.
 *
 *   This module is the status codec; verifying the response signature is
 *   c509_rev_verify_ed25519() (c509-rev-verify.h) — a client should verify the
 *   signature *and* match the response's (issuer,serial) to its query.
 *
 *   Self-contained: only the shared c509-cbor-lite walker + stdint/stddef, no
 *   os/services/c509/cbor.h, so it links into EDHOC/OSCORE/DTLS clients.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_OCSP_H
#define C509_OCSP_H

#include <stdint.h>
#include <stddef.h>

/** Certificate status (draft `CertStatus`). */
typedef enum {
  C509_OCSP_GOOD = 0,
  C509_OCSP_NOT_ISSUED = 1,
  C509_OCSP_UNKNOWN = 2,
  C509_OCSP_REVOKED = 3
} c509_ocsp_status_t;

/** Result of a status lookup. */
typedef struct {
  c509_ocsp_status_t status;
  uint64_t revocation_time;    /**< valid iff status == C509_OCSP_REVOKED */
  int64_t revocation_reason;   /**< valid iff status == C509_OCSP_REVOKED */
} c509_ocsp_result_t;

/** \brief Response type discriminator: 0 (Error), 1 (Basic), 2 (Simple), or -1. */
int c509_ocsp_resp_type(const uint8_t *buf, size_t len);

/**
 * \brief Read the responseStatus of a `C509ErrorOCSPResponse`.
 * \return 0 on success (status in \p status_out), -1 if not an Error response.
 */
int c509_ocsp_error_status(const uint8_t *buf, size_t len, int64_t *status_out);

/**
 * \brief Look up a certificate's status in a Basic or Simple OCSP response.
 *
 * Matches the target by exact (issuerCertHash, serialNumberHash) bytes.
 *
 * \param buf               the full OCSP response array.
 * \param len               length of \p buf.
 * \param issuer_cert_hash  the target's issuerCertHash bytes.
 * \param issuer_hash_len   its length.
 * \param serial_number_hash the target's serialNumberHash bytes.
 * \param serial_hash_len   its length.
 * \param result            out: the matched status (+ revocation info).
 * \return 0 on a match (result filled), 1 if no entry matches, -1 on error
 *         (malformed, or an Error/typeless response).
 */
int c509_ocsp_lookup(const uint8_t *buf, size_t len,
                     const uint8_t *issuer_cert_hash, size_t issuer_hash_len,
                     const uint8_t *serial_number_hash, size_t serial_hash_len,
                     c509_ocsp_result_t *result);

#endif /* C509_OCSP_H */
