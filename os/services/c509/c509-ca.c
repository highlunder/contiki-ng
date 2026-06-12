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

#include "c509-ca.h"
#include "c509-cbor-writer.h"
#include "c509_registry.h"
#include <string.h>

#include "lib/sha-256.h"
#include "os/net/security/micro-ecc/uECC.h"

/* uECC_HashContext callbacks backed by the platform SHA-256 driver — see
 * c509-csr-build.c for the rationale (uECC's RFC 6979 HMAC-DRBG only does
 * sequential init -> update* -> finish, never nested/concurrent, so the
 * singleton SHA_256 driver is sufficient). */
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

int c509_ca_issue_cert(uint8_t *buffer, size_t size, size_t *offset,
                       const uint8_t *serial, size_t serial_len,
                       const uint8_t *issuer, size_t issuer_len,
                       int64_t not_before, int64_t not_after,
                       const uint8_t *subject, size_t subject_len,
                       int64_t pk_alg_id,
                       const uint8_t *pk_key, size_t pk_key_len,
                       const uint8_t *ca_priv_key, size_t ca_priv_key_len) {
    if (pk_alg_id != C509_PK_SECP256R1 || pk_key_len != 65) return -1;
    if (ca_priv_key_len != 32) return -1;

    /* 0: type = 2 (Type-2, natively signed) */
    if (write_cbor_int(buffer, size, offset, 2) != 0) return -1;

    /* 1: serialNumber: bstr */
    if (write_cbor_header(buffer, size, offset, 0x40, serial_len) != 0) return -1;
    if (*offset + serial_len > size) return -1;
    memcpy(buffer + *offset, serial, serial_len); *offset += serial_len;

    /* 2: issuerSignatureAlgorithm = ecdsa-with-sha256 */
    if (write_cbor_int(buffer, size, offset, C509_SIG_ECDSA_SHA256) != 0) return -1;

    /* 3: issuer: tstr */
    if (write_cbor_header(buffer, size, offset, 0x60, issuer_len) != 0) return -1;
    if (*offset + issuer_len > size) return -1;
    memcpy(buffer + *offset, issuer, issuer_len); *offset += issuer_len;

    /* 4: notBefore */
    if (write_cbor_int(buffer, size, offset, not_before) != 0) return -1;

    /* 5: notAfter */
    if (write_cbor_int(buffer, size, offset, not_after) != 0) return -1;

    /* 6: subject: tstr */
    if (write_cbor_header(buffer, size, offset, 0x60, subject_len) != 0) return -1;
    if (*offset + subject_len > size) return -1;
    memcpy(buffer + *offset, subject, subject_len); *offset += subject_len;

    /* 7: subjectPublicKeyAlgorithm */
    if (write_cbor_int(buffer, size, offset, pk_alg_id) != 0) return -1;

    /* 8: subjectPublicKey: bstr, C509-compressed (0xFE/0xFD + X) */
    {
        const uint8_t *x = pk_key + 1;
        const uint8_t *y = pk_key + 33;
        uint8_t compressed[33];
        compressed[0] = (y[31] & 1) ? 0xFD : 0xFE;
        memcpy(compressed + 1, x, 32);

        if (write_cbor_header(buffer, size, offset, 0x40, sizeof(compressed)) != 0) return -1;
        if (*offset + sizeof(compressed) > size) return -1;
        memcpy(buffer + *offset, compressed, sizeof(compressed)); *offset += sizeof(compressed);
    }

    /* 9: extensions = null */
    if (write_cbor_header(buffer, size, offset, 0xE0, 22) != 0) return -1; /* 0xf6 */

    size_t tbs_len = *offset;

    /* sigValue: 64-byte placeholder, filled in below */
    if (write_cbor_header(buffer, size, offset, 0x40, 64) != 0) return -1;
    if (*offset + 64 > size) return -1;
    size_t sig_off = *offset;
    *offset += 64;

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
    if (!uECC_sign_deterministic(ca_priv_key, hash, sizeof(hash), &ctx, sig, uECC_secp256r1())) {
        return -1;
    }

    memcpy(buffer + sig_off, sig, sizeof(sig));
    return 0;
}
