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

#include "c509-csr-build.h"
#include "c509-cbor-writer.h"
#include "c509_registry.h"
#include <string.h>

#include "lib/sha-256.h"
#include "os/net/security/micro-ecc/uECC.h"

int x509_encode_csr_build(uint8_t *buffer, size_t size, size_t *offset,
                          const uint8_t *subject, size_t subject_len,
                          int64_t pk_alg_id,
                          const uint8_t *pk_key, size_t pk_key_len,
                          size_t *tbs_len) {
    /* type = 3 (X.509-encoded CSR, draft-ietf-cose-cbor-encoded-cert §8) */
    if (write_cbor_int(buffer, size, offset, 3) != 0) return -1;

    /* subjectSignatureAlgorithm = ecdsa-with-sha256 */
    if (write_cbor_int(buffer, size, offset, C509_SIG_ECDSA_SHA256) != 0) return -1;

    /* subject: tstr (decoded as a single CN=<subject> RDN by x509_encode_name) */
    if (write_cbor_header(buffer, size, offset, 0x60, subject_len) != 0) return -1;
    if (*offset + subject_len > size) return -1;
    memcpy(buffer + *offset, subject, subject_len); *offset += subject_len;

    /* subjectPublicKeyAlgorithm */
    if (write_cbor_int(buffer, size, offset, pk_alg_id) != 0) return -1;

    /* subjectPublicKey: bstr */
    if (write_cbor_header(buffer, size, offset, 0x40, pk_key_len) != 0) return -1;
    if (*offset + pk_key_len > size) return -1;
    memcpy(buffer + *offset, pk_key, pk_key_len); *offset += pk_key_len;

    /* attributes: empty array (no extensionRequest/challengePassword/PoP) */
    if (write_cbor_header(buffer, size, offset, 0x80, 0) != 0) return -1;

    if (tbs_len) *tbs_len = *offset;

    /* sigValue: 64-byte all-zero placeholder, filled in by x509_csr_sign() */
    if (write_cbor_header(buffer, size, offset, 0x40, 64) != 0) return -1;
    if (*offset + 64 > size) return -1;
    memset(buffer + *offset, 0, 64); *offset += 64;

    return 0;
}

/* uECC_HashContext callbacks backed by the platform SHA-256 driver
 * (os/lib/sha-256.c). uECC's RFC 6979 HMAC-DRBG (uECC.c: HMAC_init/
 * HMAC_update/HMAC_finish/update_V) only ever calls these in strictly
 * sequential init -> update* -> finish cycles, never nested or concurrent,
 * so the singleton SHA_256 driver (single global session) is sufficient. */
static void uecc_sha256_init(const uECC_HashContext *context) {
    (void)context;
    SHA_256.init();
}

static void uecc_sha256_update(const uECC_HashContext *context,
                                const uint8_t *message, unsigned message_size) {
    (void)context;
    SHA_256.update(message, message_size);
}

static void uecc_sha256_finish(const uECC_HashContext *context, uint8_t *hash_result) {
    (void)context;
    SHA_256.finalize(hash_result);
}

int x509_csr_sign(uint8_t *buffer, size_t tbs_len, size_t total_len,
                  const uint8_t *priv_key, size_t priv_key_len) {
    /* sigValue = 2-byte bstr(64) header (0x58 0x40) + 64 bytes r||s */
    if (total_len < tbs_len + 2 + 64) return -1;
    if (priv_key_len != 32) return -1;

    uint8_t hash[32];
    sha_256_hash(buffer, tbs_len, hash);

    uint8_t tmp[2 * SHA_256_DIGEST_LENGTH + SHA_256_BLOCK_SIZE];
    uECC_HashContext ctx = {
        .init_hash = uecc_sha256_init,
        .update_hash = uecc_sha256_update,
        .finish_hash = uecc_sha256_finish,
        .block_size = SHA_256_BLOCK_SIZE,
        .result_size = SHA_256_DIGEST_LENGTH,
        .tmp = tmp,
    };

    uint8_t sig[64];
    if (!uECC_sign_deterministic(priv_key, hash, sizeof(hash), &ctx, sig, uECC_secp256r1())) {
        return -1;
    }

    memcpy(buffer + (total_len - 64), sig, 64);
    return 0;
}
