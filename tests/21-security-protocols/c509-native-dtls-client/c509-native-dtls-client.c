/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   CoAPS client for native C509 Type-2 DTLS test (Cooja, native target).
 *
 *   Waits for RPL to converge, resolves the DAG root address, then opens
 *   a DTLS session to the server (c509-native-dtls-server, node 2) and
 *   issues a CoAP GET /test/hello.  On success logs the PASS string.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "coap-keystore.h"
#include "mbedtls-support/mbedtls-support.h"
#include "edhoc-cred-c509-native-test.h"

#include "sys/log.h"
#define LOG_MODULE "C509-Nat-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define CONNECT_DELAY_S    15
#define HANDSHAKE_TIMEOUT_S 120

/*---------------------------------------------------------------------------*/
static const uint8_t s_ca_pub_x[32] = C509_NATIVE_CA_PUB_X;
static const uint8_t s_ca_pub_y[32] = C509_NATIVE_CA_PUB_Y;
static uint8_t s_ca_pub_xy[64];

static int
get_c509_info(const coap_endpoint_t *ep, coap_keystore_c509_entry_t *info)
{
  info->ca_cert       = c509_native_ca_cert;
  info->ca_cert_len   = sizeof(c509_native_ca_cert);
  info->own_cert      = c509_native_client_cert;
  info->own_cert_len  = sizeof(c509_native_client_cert);
  info->peer_cert     = c509_native_server_cert;
  info->peer_cert_len = sizeof(c509_native_server_cert);
  info->priv_key      = c509_native_client_priv_key_der;
  info->priv_key_len  = sizeof(c509_native_client_priv_key_der);
  info->ca_pub_xy     = s_ca_pub_xy;
  return 1;
}

static const coap_keystore_t client_keystore = {
  .coap_get_psk_info  = NULL,
  .coap_get_cert_info = NULL,
  .coap_get_c509_info = get_c509_info,
};

/*---------------------------------------------------------------------------*/
static coap_endpoint_t server_ep;

static void
response_handler(coap_message_t *response)
{
  const uint8_t *payload;
  int len;

  if(response == NULL) {
    LOG_ERR("Request timed out\n");
    return;
  }
  len = coap_get_payload(response, &payload);
  LOG_INFO("Response: %.*s\n", len, (char *)payload);
  LOG_INFO("=== Native C509 Type-2 DTLS test PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(c509_native_dtls_client, "Native C509 Type-2 DTLS Client");
AUTOSTART_PROCESSES(&c509_native_dtls_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(c509_native_dtls_client, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;

  PROCESS_BEGIN();

  memcpy(s_ca_pub_xy,      s_ca_pub_x, 32);
  memcpy(s_ca_pub_xy + 32, s_ca_pub_y, 32);

  LOG_INFO("Starting native C509 Type-2 DTLS client\n");

  coap_engine_init();
  coap_set_keystore(&client_keystore);

  /* Wait for RPL to form and become reachable. */
  etimer_set(&et, CLOCK_SECOND * 5);
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
  }
  LOG_INFO("Network ready\n");

  /* Resolve the DAG root (server) global address. */
  uip_ipaddr_t root_addr;
  NETSTACK_ROUTING.get_root_ipaddr(&root_addr);

  uip_ipaddr_copy(&server_ep.ipaddr, &root_addr);
  server_ep.port   = UIP_HTONS(COAP_DEFAULT_SECURE_PORT);
  server_ep.secure = 1;

  /* Brief delay so the server finishes its DTLS setup. */
  etimer_set(&et, CLOCK_SECOND * CONNECT_DELAY_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  LOG_INFO("Connecting to server over CoAPS\n");
  if(!coap_endpoint_connect(&server_ep)) {
    LOG_ERR("coap_endpoint_connect failed\n");
    PROCESS_EXIT();
  }

  /* Poll until DTLS handshake completes. */
  etimer_set(&et, CLOCK_SECOND);
  {
    static int ticks;
    ticks = 0;
    while(!coap_endpoint_is_connected(&server_ep)) {
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
      etimer_reset(&et);
      if(++ticks >= HANDSHAKE_TIMEOUT_S) {
        LOG_ERR("DTLS handshake timed out\n");
        PROCESS_EXIT();
      }
    }
  }
  LOG_INFO("DTLS handshake complete\n");

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "test/hello");
  LOG_INFO("Sending GET /test/hello\n");
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
