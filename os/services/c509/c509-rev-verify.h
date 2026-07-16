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
 *   Signature verification for the flat-array C509 revocation objects
 *   (C509 CRL and the signed C509 OCSP request/response). Each is a CBOR
 *   `array[N]` whose first `N-1` elements are the `TBS*` group and whose last
 *   element is the `signatureValue` byte string; the signature is over the CBOR
 *   **sequence** of the first `N-1` elements (their concatenated bytes, without
 *   an array wrapper) — see draft-liao-cose-c509-revocation. This module locates
 *   that TBS range and the signature in place and verifies them.
 *
 *   Self-contained apart from the Ed25519 primitive (ed25519_verify.c) and the
 *   shared c509-cbor-lite walker — no os/services/c509/cbor.h, so it links into
 *   EDHOC/OSCORE/DTLS clients without the `cbor_major_type_t` collision.
 *
 *   v1 covers Ed25519 (the signature algorithm of the draft's published example
 *   keys, hence the cross-impl KAT). An ECDSA-P256 path can be added the same
 *   way (locate identically; verify with the existing uECC/SHA-256 helpers).
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_REV_VERIFY_H
#define C509_REV_VERIFY_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Locate the signed TBS range and the signatureValue of a flat-array
 *        C509 revocation object.
 *
 * \param buf      the full CBOR `array[N]` object.
 * \param len      length of \p buf.
 * \param tbs      out: pointer to the first TBS byte (points into \p buf).
 * \param tbs_len  out: length of the TBS CBOR sequence (elements 1..N-1).
 * \param sig      out: pointer to the signatureValue bytes.
 * \param sig_len  out: length of the signatureValue.
 * \return 0 on success, -1 on malformed input.
 */
int c509_rev_locate_tbs(const uint8_t *buf, size_t len,
                        const uint8_t **tbs, size_t *tbs_len,
                        const uint8_t **sig, size_t *sig_len);

/**
 * \brief Verify a flat-array C509 revocation object's Ed25519 signature.
 *
 * \param buf  the full CBOR `array[N]` object (CRL / signed OCSP req / resp).
 * \param len  length of \p buf.
 * \param pk   32-byte Ed25519 public key of the signer (CA / responder).
 * \return 0 if the signature is valid, -1 otherwise (malformed, wrong signature
 *         length, or verification failure).
 */
int c509_rev_verify_ed25519(const uint8_t *buf, size_t len,
                            const uint8_t pk[32]);

#endif /* C509_REV_VERIFY_H */
