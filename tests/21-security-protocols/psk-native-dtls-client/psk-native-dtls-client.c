/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   CoAPS client for PSK DTLS test (Exp RW-3: S3K ROM comparison).
 *
 *   Scenario E: DTLS 1.2 with pre-shared key. No certificates, no
 *   C509 codec, no uECC. Connects to psk-native-dtls-server and
 *   issues a CoAP GET /test/hello.
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

#include "sys/log.h"
#define LOG_MODULE "PSK-Nat-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define CONNECT_DELAY_S    15
#define HANDSHAKE_TIMEOUT_S 120

/* Must match the server's PSK key and identity exactly */
static const uint8_t psk_key[]      = { 0x01, 0x02, 0x03, 0x04,
                                        0x05, 0x06, 0x07, 0x08,
                                        0x09, 0x0a, 0x0b, 0x0c,
                                        0x0d, 0x0e, 0x0f, 0x10 };
static const uint8_t psk_identity[] = { 'c', 'l', 'i', 'e', 'n', 't' };

/*---------------------------------------------------------------------------*/
static int
get_psk_info(const coap_endpoint_t *ep, coap_keystore_psk_entry_t *info)
{
  info->identity_hint     = NULL;
  info->identity_hint_len = 0;
  info->identity          = psk_identity;
  info->identity_len      = sizeof(psk_identity);
  info->key               = psk_key;
  info->key_len           = sizeof(psk_key);
  return 1;
}

static const coap_keystore_t client_keystore = {
  .coap_get_psk_info  = get_psk_info,
  .coap_get_cert_info = NULL,
  .coap_get_c509_info = NULL,
};

/*---------------------------------------------------------------------------*/
static coap_endpoint_t server_ep;

static void
response_handler(coap_message_t *response)
{
  if(response == NULL) {
    LOG_ERR("Request timed out\n");
    return;
  }
  const uint8_t *payload;
  int len = coap_get_payload(response, &payload);
  LOG_INFO("Response: %.*s\n", len, (char *)payload);
  LOG_INFO("=== PSK DTLS native test PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(psk_native_dtls_client, "Native PSK DTLS Client");
AUTOSTART_PROCESSES(&psk_native_dtls_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(psk_native_dtls_client, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;
  static int ticks;

  PROCESS_BEGIN();

  LOG_INFO("Starting native PSK DTLS client\n");

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

  LOG_INFO("Connecting to server over CoAPS (PSK)\n");
  if(!coap_endpoint_connect(&server_ep)) {
    LOG_ERR("coap_endpoint_connect failed\n");
    PROCESS_EXIT();
  }

  /* Poll until DTLS handshake completes. */
  etimer_set(&et, CLOCK_SECOND);
  ticks = 0;
  while(!coap_endpoint_is_connected(&server_ep)) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
    if(++ticks >= HANDSHAKE_TIMEOUT_S) {
      LOG_ERR("DTLS handshake timed out\n");
      PROCESS_EXIT();
    }
  }
  LOG_INFO("DTLS PSK handshake complete\n");

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "test/hello");
  LOG_INFO("Sending GET /test/hello\n");
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

  coap_endpoint_disconnect(&server_ep);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
