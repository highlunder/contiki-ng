/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB.
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
 * ARE DISCLAIMED. IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
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
 *   OSCORE object security for CoAP (RFC 8613).
 *
 *   Implements key derivation from EDHOC-exported material and
 *   AEAD protect/unprotect for CoAP request/response pairs.
 *
 *   Algorithm fixed to AES-128-CCM-8 (COSE alg 10), which matches
 *   EDHOC cipher suite 2 (the default for secp256r1 deployments).
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef OSCORE_H_
#define OSCORE_H_

#include <stdint.h>
#include <stddef.h>
#include "edhoc-exporter.h"   /* oscore_ctx_t, OSCORE_KEY_SZ, OSCORE_SALT_SZ */

/* AES-128-CCM-8 parameters (COSE alg 10). */
#define OSCORE_KEY_LEN    16   /* AES-128 */
#define OSCORE_IV_LEN     13   /* CCM nonce length */
#define OSCORE_TAG_LEN     8   /* CCM-8 tag length */

/* RFC 8613 §3.1: sender/recipient IDs are 0–7 bytes. */
#define OSCORE_MAX_ID_LEN  8

/* Maximum PIV length (5 bytes = 2^40 sequence numbers). */
#define OSCORE_MAX_PIV_LEN 5

/* Upper bound on the OSCORE option value for a request:
 * 1 flag byte + 5 PIV bytes + 7 KID bytes = 13 bytes. */
#define OSCORE_OPT_MAX_LEN 13

/**
 * \brief OSCORE Security Context (RFC 8613 §3.2).
 *
 * Holds derived key material and state for one EDHOC-established session.
 * Populated by oscore_derive_context() from the EDHOC exporter output.
 */
typedef struct oscore_security_context {
  uint8_t sender_key[OSCORE_KEY_LEN];
  uint8_t recipient_key[OSCORE_KEY_LEN];
  uint8_t common_iv[OSCORE_IV_LEN];
  uint8_t sender_id[OSCORE_MAX_ID_LEN];
  uint8_t sender_id_len;
  uint8_t recipient_id[OSCORE_MAX_ID_LEN];
  uint8_t recipient_id_len;
  uint64_t sender_seq;   /* incremented after each protected request/response */
} oscore_security_context_t;

/**
 * \brief Derive OSCORE security context from EDHOC exporter output.
 *
 * Runs HKDF-Extract(Master_Salt, Master_Secret) then HKDF-Expand three
 * times to fill sender_key, recipient_key, and common_iv (RFC 8613 §3.2.1).
 *
 * \param sctx  Output OSCORE security context.
 * \param edhoc EDHOC exporter output (master_secret, master_salt, CIDs).
 * \return 0 on success, negative on error.
 */
int oscore_derive_context(oscore_security_context_t *sctx,
                           const oscore_ctx_t *edhoc);

/**
 * \brief Protect a CoAP request with OSCORE (RFC 8613 §8.1).
 *
 * Encrypts plaintext (CoAP code + payload) and encodes the OSCORE option.
 * Increments sctx->sender_seq on success.
 *
 * \param sctx              OSCORE security context (sender side).
 * \param plaintext         Inner CoAP message: [code 1B] [payload bytes].
 * \param plaintext_len     Length of plaintext.
 * \param oscore_option     Output buffer for the OSCORE CoAP option value.
 * \param oscore_option_len In: buffer size. Out: written option bytes.
 * \param ciphertext        Output buffer (needs plaintext_len + OSCORE_TAG_LEN bytes).
 * \param ciphertext_len    In: buffer size. Out: ciphertext + tag bytes written.
 * \return 0 on success, negative on error.
 */
int oscore_protect_request(oscore_security_context_t *sctx,
                            const uint8_t *plaintext, size_t plaintext_len,
                            uint8_t *oscore_option, size_t *oscore_option_len,
                            uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * \brief Unprotect a received OSCORE request (RFC 8613 §8.2).
 *
 * Parses the OSCORE option, derives the nonce, and authenticates+decrypts.
 * On success, request_piv/request_kid are filled so the caller can use them
 * when calling oscore_protect_response().
 *
 * \param sctx                OSCORE security context (recipient side).
 * \param oscore_option       Received OSCORE CoAP option value.
 * \param oscore_option_len   Length of oscore_option.
 * \param ciphertext          Received CoAP payload (ciphertext + tag).
 * \param ciphertext_len      Length of ciphertext.
 * \param plaintext           Output buffer for decrypted inner CoAP message.
 * \param plaintext_len       In: buffer size. Out: decrypted bytes.
 * \param request_piv         Output: Partial IV from request (for response nonce).
 * \param request_piv_len     Output: length of request_piv.
 * \param request_kid         Output: KID from request (sender_id of initiator).
 * \param request_kid_len     Output: length of request_kid.
 * \return 0 on success, negative on error (including AEAD tag failure).
 */
int oscore_unprotect_request(oscore_security_context_t *sctx,
                              const uint8_t *oscore_option, size_t oscore_option_len,
                              const uint8_t *ciphertext, size_t ciphertext_len,
                              uint8_t *plaintext, size_t *plaintext_len,
                              uint8_t *request_piv, uint8_t *request_piv_len,
                              uint8_t *request_kid, uint8_t *request_kid_len);

/**
 * \brief Protect a CoAP response with OSCORE (RFC 8613 §8.3).
 *
 * Uses the request's PIV and KID to reconstruct the nonce (no new PIV;
 * the OSCORE option in the response is empty — 0 bytes).
 *
 * \param sctx              OSCORE security context (server sender side).
 * \param plaintext         Inner CoAP message: [code 1B] [payload bytes].
 * \param plaintext_len     Length of plaintext.
 * \param request_piv       Partial IV from the corresponding request.
 * \param request_piv_len   Length of request_piv.
 * \param request_kid       KID from the corresponding request (client sender_id).
 * \param request_kid_len   Length of request_kid.
 * \param ciphertext        Output buffer (needs plaintext_len + OSCORE_TAG_LEN bytes).
 * \param ciphertext_len    In: buffer size. Out: ciphertext + tag bytes written.
 * \return 0 on success, negative on error.
 */
int oscore_protect_response(oscore_security_context_t *sctx,
                             const uint8_t *plaintext, size_t plaintext_len,
                             const uint8_t *request_piv, uint8_t request_piv_len,
                             const uint8_t *request_kid, uint8_t request_kid_len,
                             uint8_t *ciphertext, size_t *ciphertext_len);

/**
 * \brief Unprotect a received OSCORE response (RFC 8613 §8.4).
 *
 * Uses the saved request_piv and request_kid to rebuild the nonce.
 * The response OSCORE option is empty (0 bytes) and is not passed here.
 *
 * \param sctx              OSCORE security context (client recipient side).
 * \param ciphertext        Received CoAP payload (ciphertext + tag).
 * \param ciphertext_len    Length of ciphertext.
 * \param request_piv       Partial IV from the original request (saved by caller).
 * \param request_piv_len   Length of request_piv.
 * \param request_kid       KID from the original request (client sender_id).
 * \param request_kid_len   Length of request_kid.
 * \param plaintext         Output buffer for decrypted inner CoAP message.
 * \param plaintext_len     In: buffer size. Out: decrypted bytes.
 * \return 0 on success, negative on error (including AEAD tag failure).
 */
int oscore_unprotect_response(oscore_security_context_t *sctx,
                               const uint8_t *ciphertext, size_t ciphertext_len,
                               const uint8_t *request_piv, uint8_t request_piv_len,
                               const uint8_t *request_kid, uint8_t request_kid_len,
                               uint8_t *plaintext, size_t *plaintext_len);

/**
 * \brief Print an OSCORE security context for debugging.
 */
void oscore_print_context(const oscore_security_context_t *sctx);

#endif /* OSCORE_H_ */
