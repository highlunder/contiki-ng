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
 * \file
 *   Test credentials for C509-based EDHOC authentication.
 *
 *   SECURITY NOTICE: These credentials are for testing purposes ONLY.
 *   The private key is publicly known. Never use in production.
 *
 *   Cert: secp256r1 Type-3 C509 (draft-ietf-cose-cbor-encoded-cert)
 *   Source: secure-endpoint-test-server/vectors.h
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef EDHOC_CRED_C509_TEST_H_
#define EDHOC_CRED_C509_TEST_H_

#include "edhoc-key-storage.h"
#include <stdint.h>
#include <string.h>

/*---------------------------------------------------------------------------*/
/* Test C509 certificate (secp256r1, Type 3, reconstructed DER-equivalent)
 * Both client and server use the same cert in this test.
 * pk_alg = 1 (secp256r1), subject_pk prefix = 0xFD (odd y).
 */
static const uint8_t c509_test_cert[] = {
  0x03, 0x42, 0x12, 0x34, 0x00, 0xf6,
  0x1a, 0x67, 0x75, 0xd7, 0x00,
  0x1a, 0x69, 0x57, 0x0a, 0x80,
  0x49, 0x00, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
  0x01,
  0x58, 0x21,
  0xfd, 0xf4, 0x13, 0x59, 0x6a, 0x87, 0x12, 0x59, 0x95, 0xb4,
  0xe0, 0xd8, 0xb7, 0xbe, 0xfb, 0xc4, 0xd6, 0xed, 0xb1, 0x1f,
  0x61, 0xaf, 0x08, 0xab, 0x32, 0x40, 0x8d, 0x4f, 0xf9, 0xf9,
  0x07, 0x8d, 0xdb,
  0x88, 0x01,
  0x54, 0x07, 0xe1, 0x2c, 0x4c, 0xac, 0xe9, 0x5c, 0x22, 0x85,
  0xec, 0x4a, 0x5b, 0x05, 0xa4, 0xa2, 0xbb, 0x0e, 0xc8, 0x7a,
  0x7a, 0x02, 0x18, 0x60, 0x23, 0x20, 0x08,
  0x81, 0x01,
  0x58, 0x40,
  0x8a, 0x25, 0xe8, 0xaa, 0xbb, 0xa4, 0xb1, 0x9b, 0x8e, 0x0d,
  0x15, 0x96, 0xa4, 0x76, 0xc2, 0xc4, 0x2f, 0x50, 0x68, 0xf5,
  0xf3, 0x45, 0x76, 0x06, 0x80, 0x6e, 0x2f, 0x28, 0x4a, 0x22,
  0xe6, 0xe7, 0xa7, 0x99, 0xb8, 0x09, 0xf4, 0x36, 0x42, 0x46,
  0xe7, 0xa0, 0x93, 0xb3, 0xcc, 0x10, 0xce, 0x28, 0xb5, 0xed,
  0x9a, 0xc5, 0xfe, 0xe2, 0x95, 0x42, 0x48, 0x3b, 0x85, 0xe6,
  0x24, 0x3b, 0xc1, 0x3f
};

/*---------------------------------------------------------------------------*/
/* Raw private key scalar (32 bytes), extracted from the ECPrivateKey DER.
 * Matches the subject_pk in c509_test_cert above.
 * Public key x: f4 13 59 6a 87 12 59 95 b4 e0 d8 b7 be fb c4 d6
 *               ed b1 1f 61 af 08 ab 32 40 8d 4f f9 f9 07 8d db
 * Public key y: ab 36 35 af d4 96 d5 65 6a 22 ef dc 3d 59 c4 48
 *               2a 99 83 6b b3 58 fb f4 ca 78 d3 93 04 36 c8 57
 */
#define C509_TEST_PRIV_KEY \
  { 0x0c, 0x19, 0x83, 0x9c, 0xb7, 0xf7, 0x8b, 0xc9, \
    0x98, 0x0b, 0x5e, 0x07, 0x8f, 0x43, 0x78, 0xd3, \
    0xf3, 0x51, 0x94, 0x11, 0x15, 0xea, 0xbc, 0x1b, \
    0xe4, 0xcd, 0xac, 0x51, 0x0f, 0x5a, 0x46, 0xec }

#define C509_TEST_PUB_X \
  { 0xf4, 0x13, 0x59, 0x6a, 0x87, 0x12, 0x59, 0x95, \
    0xb4, 0xe0, 0xd8, 0xb7, 0xbe, 0xfb, 0xc4, 0xd6, \
    0xed, 0xb1, 0x1f, 0x61, 0xaf, 0x08, 0xab, 0x32, \
    0x40, 0x8d, 0x4f, 0xf9, 0xf9, 0x07, 0x8d, 0xdb }

#define C509_TEST_PUB_Y \
  { 0xab, 0x36, 0x35, 0xaf, 0xd4, 0x96, 0xd5, 0x65, \
    0x6a, 0x22, 0xef, 0xdc, 0x3d, 0x59, 0xc4, 0x48, \
    0x2a, 0x99, 0x83, 0x6b, 0xb3, 0x58, 0xfb, 0xf4, \
    0xca, 0x78, 0xd3, 0x93, 0x04, 0x36, 0xc8, 0x57 }

/*---------------------------------------------------------------------------*/
/* Server key: KID 0x01, identity "Server".
 * c509_data and c509_len must be set at runtime to c509_test_cert.
 */
static const cose_key_t auth_c509_server_template = {
  .next = NULL,
  .kid = { 0x01 },
  .kid_sz = 1,
  .identity = { "Server" },
  .identity_sz = 6,
  .kty = 2,
  .crv = 1,
  .ecc = {
    .priv = C509_TEST_PRIV_KEY,
    .pub = {
      .x = C509_TEST_PUB_X,
      .y = C509_TEST_PUB_Y
    }
  },
  .c509_data = NULL,
  .c509_len = 0
};

/*---------------------------------------------------------------------------*/
/* Client key: KID 0x02, identity "Client".
 * Uses the same public key and cert as the server (test-only).
 * c509_data and c509_len must be set at runtime to c509_test_cert.
 */
static const cose_key_t auth_c509_client_template = {
  .next = NULL,
  .kid = { 0x02 },
  .kid_sz = 1,
  .identity = { "Client" },
  .identity_sz = 6,
  .kty = 2,
  .crv = 1,
  .ecc = {
    .priv = C509_TEST_PRIV_KEY,
    .pub = {
      .x = C509_TEST_PUB_X,
      .y = C509_TEST_PUB_Y
    }
  },
  .c509_data = NULL,
  .c509_len = 0
};

/*---------------------------------------------------------------------------*/
/* Attach c509_test_cert to a key at runtime.
 * Call this for both own and peer keys before edhoc_add_key().
 */
static inline void
c509_test_attach_cert(cose_key_t *key)
{
  key->c509_data = c509_test_cert;
  key->c509_len = sizeof(c509_test_cert);
}

#endif /* EDHOC_CRED_C509_TEST_H_ */
