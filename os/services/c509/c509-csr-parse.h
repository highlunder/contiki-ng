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
 *   Parses a flat C509 Type-3 CSR CBOR sequence (draft-ietf-cose-cbor-
 *   encoded-cert §8: `[type=3, sigAlg, subject, pkAlg, pkKey, attrs,
 *   sigValue]`), as produced by x509_encode_csr_build()/x509_csr_sign(),
 *   and verifies its proof-of-possession (PoP) self-signature.
 *
 *   Self-contained: only stdint/stddef + os/lib/sha-256.h +
 *   os/net/security/micro-ecc/uECC.h. Does NOT depend on
 *   os/services/c509/cbor.h or c509.h, so it can be linked into EDHOC/
 *   OSCORE applications without the `cbor_major_type_t` collision against
 *   os/lib/cbor.h — same rationale as c509-chain.h/.c, c509-csr-build.h/.c
 *   and c509-ca.h/.c.
 *
 *   Only the minimal CBOR encodings produced by x509_encode_csr_build()
 *   are supported: unsigned integers (major type 0, 0/1/2-byte length
 *   extension), text/byte strings (major types 2/3, 0/1/2-byte length
 *   extension), and an empty array (major type 4, length 0) for the
 *   `attrs` field.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_CSR_PARSE_H
#define C509_CSR_PARSE_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Parses the 7 flat fields of a C509 Type-3 CSR.
 *
 * All `out`-pointers (other than the size_t/int64_t scalars) point into
 * \p buf — nothing is copied.
 *
 * \param buf         CSR CBOR bytes, as produced by
 *                      x509_encode_csr_build()/x509_csr_sign().
 * \param len         Length of \p buf in bytes.
 * \param type        Out: CSR type (expected 3).
 * \param sig_alg     Out: subjectSignatureAlgorithm (expected
 *                      C509_SIG_ECDSA_SHA256).
 * \param subject     Out: pointer to the subject tstr bytes.
 * \param subject_len Out: length of the subject field.
 * \param pk_alg      Out: subjectPublicKeyAlgorithm (expected
 *                      C509_PK_SECP256R1).
 * \param pk_key      Out: pointer to the subjectPublicKey bstr bytes
 *                      (65-byte uncompressed `0x04||X||Y` for secp256r1).
 * \param pk_key_len  Out: length of \p pk_key.
 * \param tbs_len     Out: length of the TBS prefix (fields 0-5), i.e. the
 *                      number of bytes that were signed.
 * \param sig         Out: pointer to the sigValue bstr bytes (64-byte
 *                      `r||s` for secp256r1).
 * \param sig_len     Out: length of \p sig.
 * \return 0 on success, -1 on malformed/truncated input or an encoding
 *         this parser doesn't support.
 */
int c509_csr_parse(const uint8_t *buf, size_t len,
                    int64_t *type,
                    int64_t *sig_alg,
                    const uint8_t **subject, size_t *subject_len,
                    int64_t *pk_alg,
                    const uint8_t **pk_key, size_t *pk_key_len,
                    size_t *tbs_len,
                    const uint8_t **sig, size_t *sig_len);

/**
 * \brief Verifies a CSR's proof-of-possession (PoP) self-signature.
 *
 * Hashes `buf[0..tbs_len)` with sha_256_hash() (os/lib/sha-256.c) and
 * verifies the 64-byte `r||s` signature at \p sig against \p pk_key with
 * uECC_verify() (secp256r1, micro-ecc). No mbedTLS dependency.
 *
 * \param tbs_ptr    Pointer to the TBS bytes (CSR fields 0-5).
 * \param tbs_len    Length of the TBS bytes.
 * \param pk_key     Subject public key, 65-byte uncompressed EC point
 *                     (`0x04 || X || Y`).
 * \param pk_key_len Length of \p pk_key (must be 65).
 * \param sig        Pointer to the 64-byte `r||s` signature.
 * \param sig_len    Length of \p sig (must be 64).
 * \return 0 if the signature is valid, -1 otherwise (including
 *         unsupported key length/format).
 */
int c509_csr_verify_pop(const uint8_t *tbs_ptr, size_t tbs_len,
                         const uint8_t *pk_key, size_t pk_key_len,
                         const uint8_t *sig, size_t sig_len);

#endif /* C509_CSR_PARSE_H */
