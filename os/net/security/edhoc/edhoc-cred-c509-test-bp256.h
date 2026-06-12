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
 *   brainpoolP256r1 test credentials for C509-based EDHOC authentication
 *   (PLAN-c509-lice-followup.md SS5.3.3, scenario D).
 *
 *   SECURITY NOTICE: These credentials are for testing purposes ONLY.
 *   Private keys are publicly known. Never use in production.
 *
 *   Certs: brainpoolP256r1 Type-2 C509 (natively signed), distinct
 *   client/server certs both issued by EDHOC-Test-CA-BP256.
 *   Source: edhoc-cred-c509-native-test-bp256.h (cargo run -- gbp).
 *
 *   Requires EDHOC_CONF_SIGNATURE_CURVE EDHOC_CURVE_BRAINPOOLP256R1 and
 *   uECC_SUPPORTS_brainpoolP256r1=1 (see project-conf.h).
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef EDHOC_CRED_C509_TEST_BP256_H_
#define EDHOC_CRED_C509_TEST_BP256_H_

#include "edhoc-key-storage.h"
#include "edhoc-cred-c509-native-test-bp256.h"
#include <stdint.h>
#include <string.h>

/*---------------------------------------------------------------------------*/
/* COSE "crv" value for brainpoolP256r1 (see edhoc-cred-c509.c
 * COSE_CRV_BRAINPOOLP256R1); not an IANA-registered value, used only as a
 * non-1 diagnostic marker. */
#define EDHOC_TEST_CRV_BRAINPOOLP256R1 255

/*---------------------------------------------------------------------------*/
/* Server key: KID 0x24, identity "Server".
 * c509_data and c509_len must be set at runtime via
 * c509_test_bp256_attach_server_cert().
 */
static const cose_key_t auth_c509_server_template_bp256 = {
  .next = NULL,
  .kid = { 0x24 },
  .kid_sz = 1,
  .identity = { "Server" },
  .identity_sz = 6,
  .kty = 2,
  .crv = EDHOC_TEST_CRV_BRAINPOOLP256R1,
  .ecc = {
    .priv = C509_NATIVE_BP256_SERVER_PRIV_KEY,
    .pub = {
      .x = C509_NATIVE_BP256_SERVER_PUB_X,
      .y = C509_NATIVE_BP256_SERVER_PUB_Y
    }
  },
  .c509_data = NULL,
  .c509_len = 0
};

/*---------------------------------------------------------------------------*/
/* Client key: KID 0x23, identity "Client".
 * c509_data and c509_len must be set at runtime via
 * c509_test_bp256_attach_client_cert().
 */
static const cose_key_t auth_c509_client_template_bp256 = {
  .next = NULL,
  .kid = { 0x23 },
  .kid_sz = 1,
  .identity = { "Client" },
  .identity_sz = 6,
  .kty = 2,
  .crv = EDHOC_TEST_CRV_BRAINPOOLP256R1,
  .ecc = {
    .priv = C509_NATIVE_BP256_CLIENT_PRIV_KEY,
    .pub = {
      .x = C509_NATIVE_BP256_CLIENT_PUB_X,
      .y = C509_NATIVE_BP256_CLIENT_PUB_Y
    }
  },
  .c509_data = NULL,
  .c509_len = 0
};

/*---------------------------------------------------------------------------*/
/* Attach c509_native_bp256_client_cert / c509_native_bp256_server_cert to a
 * key at runtime. Call for both own and peer keys before edhoc_add_key().
 */
static inline void
c509_test_bp256_attach_client_cert(cose_key_t *key)
{
  key->c509_data = c509_native_bp256_client_cert;
  key->c509_len = sizeof(c509_native_bp256_client_cert);
}

static inline void
c509_test_bp256_attach_server_cert(cose_key_t *key)
{
  key->c509_data = c509_native_bp256_server_cert;
  key->c509_len = sizeof(c509_native_bp256_server_cert);
}

#endif /* EDHOC_CRED_C509_TEST_BP256_H_ */
