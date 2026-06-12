/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   CoAPS server for native C509 Type-2 DTLS test, brainpoolP256r1 variant
 *   (Cooja, native target).
 *
 *   Same as c509-native-dtls-server, but uses brainpoolP256r1 credentials
 *   from edhoc-cred-c509-native-test-bp256.h (PLAN-c509-lice-followup.md
 *   SS5.3.3).
 *
 *   Exposes GET /test/hello over DTLS.  Logs a pass string once the
 *   first request is served.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#include "coap-engine.h"
#include "coap-keystore.h"
#include "mbedtls-support/mbedtls-support.h"
#include "c509_registry.h"
#include "edhoc-cred-c509-native-test-bp256.h"

#include "sys/log.h"
#define LOG_MODULE "C509-Nat-Sv"
#define LOG_LEVEL  LOG_LEVEL_INFO

static bool request_served = false;

/*---------------------------------------------------------------------------*/
static void
res_get_handler(coap_message_t *request, coap_message_t *response,
                uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static const char msg[] = "Hello from native C509 Type-2 server!";

  LOG_INFO("GET /test/hello\n");
  memcpy(buffer, msg, sizeof(msg) - 1);
  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, buffer, sizeof(msg) - 1);

  if(!request_served) {
    request_served = true;
    LOG_INFO("=== Native C509 Type-2 DTLS server exchange complete ===\n");
  }
}

RESOURCE(res_hello,
         "title=\"Native C509 Hello\";rt=\"Text\"",
         res_get_handler, NULL, NULL, NULL);

/*---------------------------------------------------------------------------*/
/* C509_NATIVE_BP256_CA_PUB_{X,Y} expand to { byte, ... } so they cannot be used
 * directly inside a composite initializer; split them into separate arrays. */
static const uint8_t s_ca_pub_x[32] = C509_NATIVE_BP256_CA_PUB_X;
static const uint8_t s_ca_pub_y[32] = C509_NATIVE_BP256_CA_PUB_Y;
static uint8_t s_ca_pub_xy[64];

static int
get_c509_info(const coap_endpoint_t *ep, coap_keystore_c509_entry_t *info)
{
  info->ca_cert       = c509_native_bp256_ca_cert;
  info->ca_cert_len   = sizeof(c509_native_bp256_ca_cert);
  info->own_cert      = c509_native_bp256_server_cert;
  info->own_cert_len  = sizeof(c509_native_bp256_server_cert);
  info->peer_cert     = c509_native_bp256_client_cert;
  info->peer_cert_len = sizeof(c509_native_bp256_client_cert);
  info->priv_key      = c509_native_bp256_server_priv_key_der;
  info->priv_key_len  = sizeof(c509_native_bp256_server_priv_key_der);
  info->ca_pub_xy     = s_ca_pub_xy;
  info->ca_pk_alg     = C509_PK_BRAINPOOLP256R1;
  return 1;
}

static const coap_keystore_t server_keystore = {
  .coap_get_psk_info  = NULL,
  .coap_get_cert_info = NULL,
  .coap_get_c509_info = get_c509_info,
};

/*---------------------------------------------------------------------------*/
PROCESS(c509_native_dtls_bp256_server, "Native C509 Type-2 DTLS Server (brainpoolP256r1)");
AUTOSTART_PROCESSES(&c509_native_dtls_bp256_server);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(c509_native_dtls_bp256_server, ev, data)
{
  PROCESS_BEGIN();

  memcpy(s_ca_pub_xy,      s_ca_pub_x, 32);
  memcpy(s_ca_pub_xy + 32, s_ca_pub_y, 32);

  if(IS_NETWORK_ROUTING_ROOT) {
    NETSTACK_ROUTING.root_start();
  }

  LOG_INFO("Starting native C509 Type-2 DTLS server (brainpoolP256r1)\n");

  coap_set_keystore(&server_keystore);
  coap_engine_init();
  coap_activate_resource(&res_hello, "test/hello");

  if(!coap_secure_server_setup()) {
    LOG_ERR("DTLS server setup failed\n");
    PROCESS_EXIT();
  }
  LOG_INFO("DTLS server ready\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
