/*
 * Copyright (c) 2017, RISE SICS
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
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */

/**
 * \file
 *         API for CoAP keystore
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 */

/**
 * \addtogroup coap
 * @{
 *
 * \defgroup coap-keystore CoAP keystore API
 * @{
 *
 * The CoAP keystore API defines a common interface for retrieving
 * authorization information for CoAP/DTLS.
 */

#ifndef COAP_KEYSTORE_H_
#define COAP_KEYSTORE_H_

#include "coap-endpoint.h"

/**
 * The structure of a CoAP pre-shared key info.
 */
typedef struct {
  const uint8_t *identity_hint;
  const uint8_t *identity;
  const uint8_t *key;
  uint16_t identity_hint_len;
  uint16_t identity_len;
  uint16_t key_len;
} coap_keystore_psk_entry_t;

/**
 * The structure of a CoAP PKI certificate info.
 */
typedef struct {
  const uint8_t *ca_cert;
  const uint8_t *own_cert;
  const uint8_t *priv_key;
  uint16_t ca_cert_len;
  uint16_t own_cert_len;
  uint16_t priv_key_len;
} coap_keystore_cert_entry_t;

/**
 * The structure of a CoAP C509 certificate info.
 *
 * For DER-equivalent C509 (type 0/1/3): set ca_cert, own_cert, priv_key.
 * For natively-signed C509 (type 2): additionally set peer_cert and ca_pub_xy
 * so the DTLS layer can run a native chain check via the Mbed TLS verify callback.
 */
typedef struct {
  const uint8_t *ca_cert;
  const uint8_t *own_cert;
  const uint8_t *peer_cert;    /**< C509 bytes of the peer's cert, pre-provisioned
                                     out of band (Type-2 only). Used by
                                     c509_native_verify_cb() to run a native
                                     chain check, since Mbed TLS cannot verify
                                     the (CBOR-signed) reconstructed DER. */
  const uint8_t *intermediate_cert;      /**< C509 bytes of the intermediate
                                               (Sub) CA cert that issued
                                               own_cert, or NULL for a
                                               chain-length-0 (CA issues the
                                               leaf directly) setup. Sent to
                                               the peer alongside own_cert
                                               (Type-2 only). */
  const uint8_t *peer_intermediate_cert; /**< C509 bytes of the intermediate
                                               (Sub) CA cert that issued the
                                               peer's cert, or NULL. Used by
                                               c509_native_verify_cb() to
                                               validate the peer's 2-cert
                                               chain (Type-2 only). */
  const uint8_t *priv_key;
  const uint8_t *ca_pub_xy;   /**< CA trust anchor public key, raw 64-byte
                                    x||y coordinates (Type-2 only). Passed to
                                    c509_verify_chain() as the root of trust. */
  int64_t ca_pk_alg;          /**< CA trust anchor's C509 public key algorithm
                                    ID (e.g. C509_PK_SECP256R1,
                                    C509_PK_BRAINPOOLP256R1), Type-2 only.
                                    0 defaults to secp256r1. */
  uint16_t ca_cert_len;
  uint16_t own_cert_len;
  uint16_t peer_cert_len;     /**< Length in bytes of peer_cert. */
  uint16_t intermediate_cert_len;      /**< Length in bytes of intermediate_cert. */
  uint16_t peer_intermediate_cert_len; /**< Length in bytes of peer_intermediate_cert. */
  uint16_t priv_key_len;
} coap_keystore_c509_entry_t;

/**
 * The structure of a CoAP keystore.
 *
 * The keystore implementation provides a function callback for each type of
 * authorization supported.
 */
typedef struct {
  int (* coap_get_psk_info)(const coap_endpoint_t *address_info,
                            coap_keystore_psk_entry_t *info);
  int (* coap_get_cert_info)(const coap_endpoint_t *address_info,
                            coap_keystore_cert_entry_t *info);
  int (* coap_get_c509_info)(const coap_endpoint_t *address_info,
                            coap_keystore_c509_entry_t *info);
} coap_keystore_t;

/**
 * \brief           Set the CoAP keystore to use by CoAP.
 * \param keystore  A pointer to a CoAP keystore.
 */
void coap_set_keystore(const coap_keystore_t *keystore);

#endif /* COAP_KEYSTORE_H_ */
/** @} */
/** @} */
