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
 * @file ed25519_verify.h
 * @brief Minimal from-scratch RFC 8032 Ed25519 (PureEdDSA) signature verifier.
 *
 * Implements RFC 8032 §5.1.7 signature verification: field arithmetic over
 * GF(2^255-19), Edwards25519 curve point operations (point decoding, addition,
 * doubling, scalar multiplication), and scalar reduction modulo the group
 * order `l`. SHA-512 is provided by mbedTLS.
 *
 * Used by the C509 service (via crypto_mbedtls.c) to verify Ed25519-signed
 * C509/X.509 certificates, where mbedTLS itself does not provide a usable
 * Ed25519 verification primitive.
 */

#ifndef ED25519_VERIFY_H
#define ED25519_VERIFY_H

#include <stddef.h>
#include <stdint.h>

/**
 * Verify an Ed25519 signature per RFC 8032 §5.1.7.
 *
 * @param pk      32-byte compressed public key
 * @param sig     64-byte signature (R || s)
 * @param msg     message bytes
 * @param msg_len message length
 * @return 0 on valid, -1 on invalid
 */
int ed25519_verify(const uint8_t pk[32], const uint8_t sig[64],
                   const uint8_t *msg, size_t msg_len);

/**
 * Derive the 32-byte Ed25519 public key from a 32-byte private seed
 * (RFC 8032 §5.1.5).
 *
 * @param seed    32-byte private key seed
 * @param pub_out 32-byte output buffer for the public key
 */
void ed25519_pubkey_from_seed(const uint8_t seed[32], uint8_t pub_out[32]);

/**
 * Sign a message with Ed25519 PureEdDSA (RFC 8032 §5.1.6).
 *
 * @param seed    32-byte private key seed
 * @param msg     message bytes
 * @param msg_len message length
 * @param sig_out 64-byte output buffer for the signature (R || S)
 */
void ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len,
                   uint8_t sig_out[64]);

#endif /* ED25519_VERIFY_H */
