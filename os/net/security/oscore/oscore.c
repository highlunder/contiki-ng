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
 *   This module implements the minimum OSCORE layer needed to exchange one
 *   protected CoAP request/response pair after an EDHOC handshake:
 *
 *   Key derivation (§3.2.1):
 *     HKDF-Extract(Master_Salt, Master_Secret) → PRK
 *     HKDF-Expand(PRK, info("Key", sender_id))    → Sender Key (16 B)
 *     HKDF-Expand(PRK, info("Key", recipient_id)) → Recipient Key (16 B)
 *     HKDF-Expand(PRK, info("IV",  ""))           → Common IV (13 B)
 *
 *   Nonce (§5.2): Common_IV XOR [sid_len || pad || sid || piv5]
 *   external_aad (§5.3): CBOR([1, [10], request_kid, request_piv, h''])
 *   AEAD: AES-128-CCM-8 (COSE alg 10) via cose_encrypt0_seal/open()
 *
 *   Dependencies:
 *     lib/sha-256.h  — sha_256_hkdf_extract / sha_256_hkdf_expand
 *     lib/cbor.h     — CBOR writer for info and external_aad
 *     cose.h         — cose_encrypt0_seal / cose_encrypt0_open (CCM driver)
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include "oscore.h"
#include "lib/sha-256.h"
#include "lib/cbor.h"
#include "cose.h"             /* cose_encrypt0_seal, cose_encrypt0_open,
                                 COSE_ALG_AES_CCM_16_64_128 */
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "OSCORE"
#define LOG_LEVEL  LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
/*
 * Encode the HKDF info structure for OSCORE key/IV derivation.
 *
 * info = CBOR([algorithm_id, id_context, id, type, L])
 *
 * RFC 8613 §3.2.1: algorithm_id = 10 (AES-128-CCM-8), id_context = Master
 * Salt, id = Sender/Recipient ID (empty for IV), type = "Key"/"IV".
 */
static size_t
build_hkdf_info(const uint8_t *id_context, uint8_t id_context_len,
                const uint8_t *id, uint8_t id_len,
                const char *type, uint8_t L,
                uint8_t *out, size_t out_max)
{
  cbor_writer_state_t w;
  cbor_init_writer(&w, out, out_max);
  cbor_open_array(&w);
  cbor_write_unsigned(&w, COSE_ALG_AES_CCM_16_64_128);
  cbor_write_data(&w, id_context, id_context_len);
  cbor_write_data(&w, id, id_len);
  cbor_write_text(&w, type, strlen(type));
  cbor_write_unsigned(&w, L);
  cbor_close_array(&w);
  return cbor_end_writer(&w);
}
/*---------------------------------------------------------------------------*/
/*
 * Encode the OSCORE external_aad (RFC 8613 §5.3):
 *
 * external_aad = CBOR([
 *   1,          -- oscore_version
 *   [10],       -- algorithms: [aead_alg_id]
 *   request_kid -- bstr
 *   request_piv -- bstr
 *   h''         -- class-I options (empty)
 * ])
 */
static size_t
build_external_aad(const uint8_t *request_kid, uint8_t request_kid_len,
                   const uint8_t *request_piv, uint8_t request_piv_len,
                   uint8_t *out, size_t out_max)
{
  cbor_writer_state_t w;
  cbor_init_writer(&w, out, out_max);
  cbor_open_array(&w);
  cbor_write_unsigned(&w, 1);                            /* oscore_version */
  cbor_open_array(&w);                                   /* algorithms */
  cbor_write_unsigned(&w, COSE_ALG_AES_CCM_16_64_128);
  cbor_close_array(&w);
  cbor_write_data(&w, request_kid, request_kid_len);     /* request_kid */
  cbor_write_data(&w, request_piv, request_piv_len);     /* request_piv */
  cbor_write_data(&w, NULL, 0);                          /* class-I options */
  cbor_close_array(&w);
  return cbor_end_writer(&w);
}
/*---------------------------------------------------------------------------*/
/*
 * Compute the OSCORE nonce (RFC 8613 §5.2):
 *
 * nonce = Common_IV XOR (sender_id_len || padding || sender_id || piv5)
 *
 * where the 13-byte XOR operand is:
 *   byte 0:               sender_id_len (1 byte)
 *   bytes 1..(7-sid_len): zero padding
 *   bytes (8-sid_len)..7: sender_id (sid_len bytes)
 *   bytes 8..12:          PIV padded to 5 bytes on the left with zeros
 */
static void
build_nonce(const uint8_t *common_iv,
            const uint8_t *sender_id, uint8_t sender_id_len,
            const uint8_t *piv, uint8_t piv_len,
            uint8_t *nonce)
{
  uint8_t xor_val[OSCORE_IV_LEN];
  memset(xor_val, 0, OSCORE_IV_LEN);

  xor_val[0] = sender_id_len;

  if(sender_id_len > 0 && sender_id_len <= 7) {
    memcpy(xor_val + (8 - sender_id_len), sender_id, sender_id_len);
  }

  /* PIV right-aligned in bytes 8–12 (zero-padded on the left). */
  if(piv_len > 0 && piv_len <= OSCORE_MAX_PIV_LEN) {
    memcpy(xor_val + 8 + (OSCORE_MAX_PIV_LEN - piv_len), piv, piv_len);
  }

  for(uint8_t i = 0; i < OSCORE_IV_LEN; i++) {
    nonce[i] = common_iv[i] ^ xor_val[i];
  }
}
/*---------------------------------------------------------------------------*/
/*
 * Encode the sequence number as a minimal big-endian byte string.
 * seq=0 → h'00' (1 byte), seq=256 → h'0100' (2 bytes), etc.
 * Returns the number of bytes written (1–5).
 */
static uint8_t
encode_piv(uint64_t seq, uint8_t *piv)
{
  if(seq == 0) {
    piv[0] = 0;
    return 1;
  }
  uint8_t tmp[OSCORE_MAX_PIV_LEN];
  uint8_t len = 0;
  uint64_t s = seq;
  while(s > 0 && len < OSCORE_MAX_PIV_LEN) {
    tmp[len++] = (uint8_t)(s & 0xFF);
    s >>= 8;
  }
  for(uint8_t i = 0; i < len; i++) {
    piv[i] = tmp[len - 1 - i];
  }
  return len;
}
/*---------------------------------------------------------------------------*/
int
oscore_derive_context(oscore_security_context_t *sctx, const oscore_ctx_t *edhoc)
{
  /* PRK = HKDF-Extract(salt=Master_Salt, ikm=Master_Secret) */
  uint8_t prk[SHA_256_DIGEST_LENGTH];
  sha_256_hkdf_extract(edhoc->master_salt, OSCORE_SALT_SZ,
                        edhoc->master_secret, OSCORE_KEY_SZ, prk);

  sctx->sender_id_len = edhoc->sender_id_len;
  memcpy(sctx->sender_id, edhoc->sender_id, edhoc->sender_id_len);
  sctx->recipient_id_len = edhoc->recipient_id_len;
  memcpy(sctx->recipient_id, edhoc->recipient_id, edhoc->recipient_id_len);
  sctx->sender_seq = 0;

  uint8_t info[64];
  size_t info_len;

  /* Sender Key */
  info_len = build_hkdf_info(edhoc->master_salt, OSCORE_SALT_SZ,
                              sctx->sender_id, sctx->sender_id_len,
                              "Key", OSCORE_KEY_LEN, info, sizeof(info));
  if(info_len == 0) {
    LOG_ERR("Failed to encode sender key info\n");
    return -1;
  }
  sha_256_hkdf_expand(prk, SHA_256_DIGEST_LENGTH, info, info_len,
                       sctx->sender_key, OSCORE_KEY_LEN);

  /* Recipient Key */
  info_len = build_hkdf_info(edhoc->master_salt, OSCORE_SALT_SZ,
                              sctx->recipient_id, sctx->recipient_id_len,
                              "Key", OSCORE_KEY_LEN, info, sizeof(info));
  if(info_len == 0) {
    LOG_ERR("Failed to encode recipient key info\n");
    return -2;
  }
  sha_256_hkdf_expand(prk, SHA_256_DIGEST_LENGTH, info, info_len,
                       sctx->recipient_key, OSCORE_KEY_LEN);

  /* Common IV (empty sender ID for IV derivation per RFC 8613 §3.2.1) */
  info_len = build_hkdf_info(edhoc->master_salt, OSCORE_SALT_SZ,
                              NULL, 0,
                              "IV", OSCORE_IV_LEN, info, sizeof(info));
  if(info_len == 0) {
    LOG_ERR("Failed to encode common IV info\n");
    return -3;
  }
  sha_256_hkdf_expand(prk, SHA_256_DIGEST_LENGTH, info, info_len,
                       sctx->common_iv, OSCORE_IV_LEN);

  return 0;
}
/*---------------------------------------------------------------------------*/
void
oscore_print_context(const oscore_security_context_t *sctx)
{
  LOG_INFO("Sender ID   (%u B): ", sctx->sender_id_len);
  LOG_INFO_BYTES(sctx->sender_id, sctx->sender_id_len);
  LOG_INFO_("\n");
  LOG_INFO("Recipient ID(%u B): ", sctx->recipient_id_len);
  LOG_INFO_BYTES(sctx->recipient_id, sctx->recipient_id_len);
  LOG_INFO_("\n");
  LOG_INFO("Sender Key  (16 B): ");
  LOG_INFO_BYTES(sctx->sender_key, OSCORE_KEY_LEN);
  LOG_INFO_("\n");
  LOG_INFO("Recipient K (16 B): ");
  LOG_INFO_BYTES(sctx->recipient_key, OSCORE_KEY_LEN);
  LOG_INFO_("\n");
  LOG_INFO("Common IV   (13 B): ");
  LOG_INFO_BYTES(sctx->common_iv, OSCORE_IV_LEN);
  LOG_INFO_("\n");
}
/*---------------------------------------------------------------------------*/
int
oscore_protect_request(oscore_security_context_t *sctx,
                        const uint8_t *plaintext, size_t plaintext_len,
                        uint8_t *oscore_option, size_t *oscore_option_len,
                        uint8_t *ciphertext, size_t *ciphertext_len)
{
  /* 1. Encode partial IV from sender sequence number. */
  uint8_t piv[OSCORE_MAX_PIV_LEN];
  uint8_t piv_len = encode_piv(sctx->sender_seq, piv);

  /* 2. Encode OSCORE option: [flag=0x08|n] [piv] [sender_id]
   *    Flag bits: k=1 (KID present), n=piv_len. */
  size_t opt_needed = 1 + piv_len + sctx->sender_id_len;
  if(opt_needed > *oscore_option_len) {
    LOG_ERR("OSCORE option buffer too small (%zu need %zu)\n",
            *oscore_option_len, opt_needed);
    return -1;
  }
  uint8_t pos = 0;
  oscore_option[pos++] = (uint8_t)(0x08 | piv_len);
  memcpy(oscore_option + pos, piv, piv_len);  pos += piv_len;
  memcpy(oscore_option + pos, sctx->sender_id, sctx->sender_id_len);
  *oscore_option_len = 1 + piv_len + sctx->sender_id_len;

  /* 3. Build external_aad from own sender_id and this PIV. */
  uint8_t ext_aad[64];
  size_t ext_aad_len = build_external_aad(sctx->sender_id, sctx->sender_id_len,
                                           piv, piv_len,
                                           ext_aad, sizeof(ext_aad));
  if(ext_aad_len == 0) {
    LOG_ERR("Failed to encode external_aad\n");
    return -2;
  }

  /* 4. Build nonce. */
  uint8_t nonce[OSCORE_IV_LEN];
  build_nonce(sctx->common_iv, sctx->sender_id, sctx->sender_id_len,
              piv, piv_len, nonce);

  /* 5. Encrypt in-place (ciphertext = plaintext; tag appended after). */
  size_t ct_needed = plaintext_len + OSCORE_TAG_LEN;
  if(ct_needed > *ciphertext_len) {
    LOG_ERR("Ciphertext buffer too small (%zu need %zu)\n",
            *ciphertext_len, ct_needed);
    return -3;
  }
  memcpy(ciphertext, plaintext, plaintext_len);
  size_t out = cose_encrypt0_seal(COSE_ALG_AES_CCM_16_64_128,
                                   sctx->sender_key, nonce,
                                   ext_aad, ext_aad_len,
                                   ciphertext, plaintext_len);
  if(out == 0) {
    LOG_ERR("AEAD seal failed\n");
    return -4;
  }
  *ciphertext_len = out;
  sctx->sender_seq++;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
oscore_unprotect_request(oscore_security_context_t *sctx,
                          const uint8_t *oscore_option, size_t oscore_option_len,
                          const uint8_t *ciphertext, size_t ciphertext_len,
                          uint8_t *plaintext, size_t *plaintext_len,
                          uint8_t *request_piv, uint8_t *request_piv_len,
                          uint8_t *request_kid, uint8_t *request_kid_len)
{
  /* 1. Parse OSCORE option. */
  if(oscore_option_len < 1) {
    LOG_ERR("OSCORE option too short\n");
    return -1;
  }
  uint8_t flags   = oscore_option[0];
  uint8_t n       = flags & 0x07;  /* PIV length */
  uint8_t k       = (flags >> 3) & 1;

  if((size_t)(1 + n) > oscore_option_len) {
    LOG_ERR("OSCORE option truncated (n=%u, len=%zu)\n", n, oscore_option_len);
    return -2;
  }
  *request_piv_len = n;
  memcpy(request_piv, oscore_option + 1, n);

  if(k) {
    size_t kid_len = oscore_option_len - 1 - n;
    if(kid_len > OSCORE_MAX_ID_LEN) {
      LOG_ERR("KID too long (%zu)\n", kid_len);
      return -3;
    }
    *request_kid_len = (uint8_t)kid_len;
    memcpy(request_kid, oscore_option + 1 + n, kid_len);
  } else {
    *request_kid_len = 0;
  }

  /* 2. Build external_aad from the sender's KID and PIV. */
  uint8_t ext_aad[64];
  size_t ext_aad_len = build_external_aad(request_kid, *request_kid_len,
                                           request_piv, *request_piv_len,
                                           ext_aad, sizeof(ext_aad));
  if(ext_aad_len == 0) {
    LOG_ERR("Failed to encode external_aad\n");
    return -4;
  }

  /* 3. Build nonce: use request_kid (sender_id of initiator) and request_piv. */
  uint8_t nonce[OSCORE_IV_LEN];
  build_nonce(sctx->common_iv, request_kid, *request_kid_len,
              request_piv, *request_piv_len, nonce);

  /* 4. Decrypt in-place using recipient key. */
  if(ciphertext_len <= OSCORE_TAG_LEN) {
    LOG_ERR("Ciphertext too short\n");
    return -5;
  }
  if(ciphertext_len > *plaintext_len) {
    LOG_ERR("Plaintext buffer too small\n");
    return -6;
  }
  memcpy(plaintext, ciphertext, ciphertext_len);
  size_t out = cose_encrypt0_open(COSE_ALG_AES_CCM_16_64_128,
                                   sctx->recipient_key, nonce,
                                   ext_aad, ext_aad_len,
                                   plaintext, ciphertext_len);
  if(out == 0) {
    LOG_ERR("AEAD open failed (tag mismatch or bad input)\n");
    return -7;
  }
  *plaintext_len = out;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
oscore_protect_response(oscore_security_context_t *sctx,
                         const uint8_t *plaintext, size_t plaintext_len,
                         const uint8_t *request_piv, uint8_t request_piv_len,
                         const uint8_t *request_kid, uint8_t request_kid_len,
                         uint8_t *ciphertext, size_t *ciphertext_len)
{
  /* RFC 8613 §8.3: response nonce = Common_IV XOR (request_kid, request_piv).
   * The response OSCORE option is empty (caller sets option to 0 bytes). */

  uint8_t ext_aad[64];
  size_t ext_aad_len = build_external_aad(request_kid, request_kid_len,
                                           request_piv, request_piv_len,
                                           ext_aad, sizeof(ext_aad));
  if(ext_aad_len == 0) {
    LOG_ERR("Failed to encode external_aad\n");
    return -1;
  }

  uint8_t nonce[OSCORE_IV_LEN];
  build_nonce(sctx->common_iv, request_kid, request_kid_len,
              request_piv, request_piv_len, nonce);

  size_t ct_needed = plaintext_len + OSCORE_TAG_LEN;
  if(ct_needed > *ciphertext_len) {
    LOG_ERR("Ciphertext buffer too small\n");
    return -2;
  }
  memcpy(ciphertext, plaintext, plaintext_len);
  size_t out = cose_encrypt0_seal(COSE_ALG_AES_CCM_16_64_128,
                                   sctx->sender_key, nonce,
                                   ext_aad, ext_aad_len,
                                   ciphertext, plaintext_len);
  if(out == 0) {
    LOG_ERR("AEAD seal failed\n");
    return -3;
  }
  *ciphertext_len = out;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
oscore_unprotect_response(oscore_security_context_t *sctx,
                           const uint8_t *ciphertext, size_t ciphertext_len,
                           const uint8_t *request_piv, uint8_t request_piv_len,
                           const uint8_t *request_kid, uint8_t request_kid_len,
                           uint8_t *plaintext, size_t *plaintext_len)
{
  /* Nonce reconstructed identically to how the server computed it. */
  uint8_t ext_aad[64];
  size_t ext_aad_len = build_external_aad(request_kid, request_kid_len,
                                           request_piv, request_piv_len,
                                           ext_aad, sizeof(ext_aad));
  if(ext_aad_len == 0) {
    LOG_ERR("Failed to encode external_aad\n");
    return -1;
  }

  uint8_t nonce[OSCORE_IV_LEN];
  build_nonce(sctx->common_iv, request_kid, request_kid_len,
              request_piv, request_piv_len, nonce);

  if(ciphertext_len <= OSCORE_TAG_LEN) {
    LOG_ERR("Ciphertext too short\n");
    return -2;
  }
  if(ciphertext_len > *plaintext_len) {
    LOG_ERR("Plaintext buffer too small\n");
    return -3;
  }
  memcpy(plaintext, ciphertext, ciphertext_len);
  /* Client uses recipient_key to decrypt response (= server's sender_key). */
  size_t out = cose_encrypt0_open(COSE_ALG_AES_CCM_16_64_128,
                                   sctx->recipient_key, nonce,
                                   ext_aad, ext_aad_len,
                                   plaintext, ciphertext_len);
  if(out == 0) {
    LOG_ERR("AEAD open failed\n");
    return -4;
  }
  *plaintext_len = out;
  return 0;
}
/*---------------------------------------------------------------------------*/
