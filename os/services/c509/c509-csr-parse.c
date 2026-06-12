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

#include "c509-csr-parse.h"

#include "lib/sha-256.h"
#include "os/net/security/micro-ecc/uECC.h"

/* Reads one CBOR item header: major type (top 3 bits) and the
 * argument/length value, supporting additional-info 0-23 (inline), 24
 * (1-byte extension) and 25 (2-byte extension) — sufficient for the
 * encodings produced by x509_encode_csr_build(). */
static int read_cbor_header(const uint8_t *buf, size_t len, size_t *offset,
                             uint8_t *major, uint64_t *value) {
    if (*offset >= len) return -1;
    uint8_t b = buf[*offset];
    *major = b >> 5;
    uint8_t ai = b & 0x1f;
    (*offset)++;

    if (ai < 24) {
        *value = ai;
        return 0;
    }
    if (ai == 24) {
        if (*offset + 1 > len) return -1;
        *value = buf[*offset]; (*offset)++;
        return 0;
    }
    if (ai == 25) {
        if (*offset + 2 > len) return -1;
        *value = ((uint64_t)buf[*offset] << 8) | buf[*offset + 1];
        (*offset) += 2;
        return 0;
    }
    return -1;
}

int c509_csr_parse(const uint8_t *buf, size_t len,
                    int64_t *type,
                    int64_t *sig_alg,
                    const uint8_t **subject, size_t *subject_len,
                    int64_t *pk_alg,
                    const uint8_t **pk_key, size_t *pk_key_len,
                    size_t *tbs_len,
                    const uint8_t **sig, size_t *sig_len) {
    size_t offset = 0;
    uint8_t major;
    uint64_t value;

    /* 0: type */
    if (read_cbor_header(buf, len, &offset, &major, &value) != 0 || major != 0) return -1;
    if (type) *type = (int64_t)value;

    /* 1: subjectSignatureAlgorithm */
    if (read_cbor_header(buf, len, &offset, &major, &value) != 0 || major != 0) return -1;
    if (sig_alg) *sig_alg = (int64_t)value;

    /* 2: subject (tstr) */
    if (read_cbor_header(buf, len, &offset, &major, &value) != 0 || major != 3) return -1;
    if (offset + value > len) return -1;
    if (subject) *subject = buf + offset;
    if (subject_len) *subject_len = (size_t)value;
    offset += value;

    /* 3: subjectPublicKeyAlgorithm */
    if (read_cbor_header(buf, len, &offset, &major, &value) != 0 || major != 0) return -1;
    if (pk_alg) *pk_alg = (int64_t)value;

    /* 4: subjectPublicKey (bstr) */
    if (read_cbor_header(buf, len, &offset, &major, &value) != 0 || major != 2) return -1;
    if (offset + value > len) return -1;
    if (pk_key) *pk_key = buf + offset;
    if (pk_key_len) *pk_key_len = (size_t)value;
    offset += value;

    /* 5: attributes (array) — only the empty array is supported */
    if (read_cbor_header(buf, len, &offset, &major, &value) != 0 || major != 4) return -1;
    if (value != 0) return -1;

    if (tbs_len) *tbs_len = offset;

    /* 6: sigValue (bstr) */
    if (read_cbor_header(buf, len, &offset, &major, &value) != 0 || major != 2) return -1;
    if (offset + value > len) return -1;
    if (sig) *sig = buf + offset;
    if (sig_len) *sig_len = (size_t)value;
    offset += value;

    return 0;
}

int c509_csr_verify_pop(const uint8_t *tbs_ptr, size_t tbs_len,
                         const uint8_t *pk_key, size_t pk_key_len,
                         const uint8_t *sig, size_t sig_len) {
    if (pk_key_len != 65 || pk_key[0] != 0x04) return -1;
    if (sig_len != 64) return -1;

    uint8_t hash[32];
    sha_256_hash(tbs_ptr, tbs_len, hash);

    if (!uECC_verify(pk_key + 1, hash, sizeof(hash), sig, uECC_secp256r1())) {
        return -1;
    }
    return 0;
}
