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
 *   Test credentials for C509-based EDHOC authentication with a
 *   chain-length-2 certificate chain (c5c, scenario D chain2 variant).
 *
 *   SECURITY NOTICE: These credentials are for testing purposes ONLY.
 *   The private keys are publicly known. Never use in production.
 *
 *   Chain: Test-Root-CA-2 (trust anchor, out-of-band)
 *            -> Test-Sub-CA-1 -> Test-Sub-CA-2 -> Client2 / Server2
 *   On the wire (c5c CRED_x), each peer sends [leaf cert, Sub CA 2 cert,
 *   Sub CA 1 cert] as a CBOR array of byte strings. The Root CA 2 public
 *   key is the out-of-band trust anchor, registered via
 *   edhoc_set_c509_trust_store() together with edhoc_c509_validate_chain()
 *   as the cert validator.
 *
 *   Source certs/keys: c509-native-chain2-test.h
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef EDHOC_CRED_C509_TEST_CHAIN2_H_
#define EDHOC_CRED_C509_TEST_CHAIN2_H_

#include "edhoc-key-storage.h"
#include "edhoc-trust-store.h"
#include "c509-native-chain2-test.h"
#include "lib/cbor.h"
#include <stdint.h>
#include <string.h>

/*---------------------------------------------------------------------------*/
/* Client key: KID 0x43, identity "Client2". c509_data/c509_len are set at
 * runtime (by c509_chain2_test_attach_client_cert()) to the CBOR array
 * [bstr<client_cert>, bstr<sub_ca2_cert>, bstr<sub_ca1_cert>]. */
static const cose_key_t auth_c509_chain2_client_template = {
  .next = NULL,
  .kid = { 0x43 },
  .kid_sz = 1,
  .identity = { "Client2" },
  .identity_sz = 7,
  .kty = 2,
  .crv = 1,
  .ecc = {
    .priv = C509_NATIVE_CHAIN2_CLIENT_PRIV_KEY,
    .pub = {
      .x = C509_NATIVE_CHAIN2_CLIENT_PUB_X,
      .y = C509_NATIVE_CHAIN2_CLIENT_PUB_Y
    }
  },
  .c509_data = NULL,
  .c509_len = 0
};

/*---------------------------------------------------------------------------*/
/* Server key: KID 0x44, identity "Server2". c509_data/c509_len are set at
 * runtime (by c509_chain2_test_attach_server_cert()) to the CBOR array
 * [bstr<server_cert>, bstr<sub_ca2_cert>, bstr<sub_ca1_cert>]. */
static const cose_key_t auth_c509_chain2_server_template = {
  .next = NULL,
  .kid = { 0x44 },
  .kid_sz = 1,
  .identity = { "Server2" },
  .identity_sz = 7,
  .kty = 2,
  .crv = 1,
  .ecc = {
    .priv = C509_NATIVE_CHAIN2_SERVER_PRIV_KEY,
    .pub = {
      .x = C509_NATIVE_CHAIN2_SERVER_PUB_X,
      .y = C509_NATIVE_CHAIN2_SERVER_PUB_Y
    }
  },
  .c509_data = NULL,
  .c509_len = 0
};

/*---------------------------------------------------------------------------*/
/* Root CA 2 trust anchor: public key only (no private key — never used for
 * signing in this test, only as the out-of-band root of trust passed to
 * edhoc_set_c509_trust_store()). */
static const cose_key_t c509_chain2_root_ca_anchor = {
  .next = NULL,
  .kid = { 0x41 },
  .kid_sz = 1,
  .identity = { "Test-Root-CA-2" },
  .identity_sz = 14,
  .kty = 2,
  .crv = 1,
  .ecc = {
    .priv = { 0 },
    .pub = {
      .x = C509_NATIVE_CHAIN2_ROOT_CA_PUB_X,
      .y = C509_NATIVE_CHAIN2_ROOT_CA_PUB_Y
    }
  },
  .c509_data = NULL,
  .c509_len = 0
};

/*---------------------------------------------------------------------------*/
/* Buffer for the on-wire c5c chain2 CRED_x:
 * CBOR array [bstr<leaf>, bstr<Sub CA 2>, bstr<Sub CA 1>].
 * Sizing: 1 (array(3) header) + 2 (bstr header, len 139) + 139 (leaf)
 *       + 2 (bstr header, len 149) + 149 (Sub CA 2)
 *       + 2 (bstr header, len 150) + 150 (Sub CA 1) = 444 bytes -> 460 (margin).
 */
#define C509_CHAIN2_C5C_CRED_BUF_LEN 460

static uint8_t c509_chain2_client_cred_buf[C509_CHAIN2_C5C_CRED_BUF_LEN];
static uint8_t c509_chain2_server_cred_buf[C509_CHAIN2_C5C_CRED_BUF_LEN];

/*---------------------------------------------------------------------------*/
/* Build CRED_x = CBOR array [bstr<leaf>, bstr<sub_ca2>, bstr<sub_ca1>] into
 * buf, and point key->c509_data/c509_len at it. Used for both c5c
 * CRED_x/ID_CRED_x generation (edhoc_c509_generate_cred_x()/
 * edhoc_c509_generate_id_cred_c5c()) on the sending side. */
static inline void
c509_chain2_test_build_cred(cose_key_t *key,
                             const uint8_t *leaf, size_t leaf_len,
                             uint8_t *buf, size_t buf_sz)
{
  cbor_writer_state_t w;
  cbor_init_writer(&w, buf, buf_sz);
  cbor_open_array(&w);
  cbor_write_data(&w, leaf, leaf_len);
  cbor_write_data(&w, c509_native_chain2_sub_ca2_cert,
                  sizeof(c509_native_chain2_sub_ca2_cert));
  cbor_write_data(&w, c509_native_chain2_sub_ca1_cert,
                  sizeof(c509_native_chain2_sub_ca1_cert));
  cbor_close_array(&w);
  size_t written = cbor_end_writer(&w);

  key->c509_data = buf;
  key->c509_len  = written;
}

/*---------------------------------------------------------------------------*/
/* Attach the [client cert, Sub CA 2 cert, Sub CA 1 cert] chain to a key at
 * runtime. Call this for the client's own key before
 * edhoc_add_key()/edhoc_setup_key_pair(). */
static inline void
c509_chain2_test_attach_client_cert(cose_key_t *key)
{
  c509_chain2_test_build_cred(key,
                               c509_native_chain2_client_cert,
                               sizeof(c509_native_chain2_client_cert),
                               c509_chain2_client_cred_buf,
                               sizeof(c509_chain2_client_cred_buf));
}

/*---------------------------------------------------------------------------*/
/* Attach the [server cert, Sub CA 2 cert, Sub CA 1 cert] chain to a key at
 * runtime. Call this for the server's own key before
 * edhoc_add_key()/edhoc_setup_key_pair(). */
static inline void
c509_chain2_test_attach_server_cert(cose_key_t *key)
{
  c509_chain2_test_build_cred(key,
                               c509_native_chain2_server_cert,
                               sizeof(c509_native_chain2_server_cert),
                               c509_chain2_server_cred_buf,
                               sizeof(c509_chain2_server_cred_buf));
}

#endif /* EDHOC_CRED_C509_TEST_CHAIN2_H_ */
