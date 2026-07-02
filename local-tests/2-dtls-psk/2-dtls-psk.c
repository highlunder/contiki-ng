/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Rung 2: DTLS + PSK over the air, against setest scenario "psk" (UDP 5686).
 *
 *   Plain RPL node: joins the Firefly DAG over 2.4 GHz, then does a CoAPS+PSK
 *   handshake to the setest host at fd00::1 (reached through the Firefly) and a
 *   CoAP GET /test/hello. Radio counterpart of phase2-slip/psk-slip-client.c
 *   (which was its own SLIP root); here the uplink is over the air.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#include "net/ipv6/uiplib.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "coap-keystore.h"
#include "local-test-banner.h"

#include "sys/log.h"
#define LOG_MODULE "2-dtls-psk"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef LOCAL_SERVER_ADDR
#define LOCAL_SERVER_ADDR "fd00::1"
#endif
#ifndef LOCAL_SERVER_PORT
#define LOCAL_SERVER_PORT 5686        /* setest scenario "psk" */
#endif
#ifndef LOCAL_SETTLE_S
#define LOCAL_SETTLE_S 5
#endif
#define HANDSHAKE_TIMEOUT_S 120

/* Must match setest/modules/dtls_psk.py and psk-native-dtls-server.c exactly. */
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
  LOG_INFO("=== 2-dtls-psk PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(dtls_psk_test, "2-dtls-psk (OTA)");
AUTOSTART_PROCESSES(&dtls_psk_test);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_psk_test, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;
  static int ticks;

  PROCESS_BEGIN();

  local_test_banner("2-dtls-psk", LOCAL_SERVER_ADDR, LOCAL_SERVER_PORT);

  coap_engine_init();
  coap_set_keystore(&client_keystore);

  /* Wait until we have joined the Firefly DAG and the root is reachable. */
  etimer_set(&et, CLOCK_SECOND);
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
    LOG_INFO("Waiting to join the DAG (radio)...\n");
  }
  LOG_INFO("Joined the DAG; root reachable, network up\n");

  if(!uiplib_ipaddrconv(LOCAL_SERVER_ADDR, &server_ep.ipaddr)) {
    LOG_ERR("Invalid LOCAL_SERVER_ADDR '%s'\n", LOCAL_SERVER_ADDR);
    PROCESS_EXIT();
  }
  server_ep.port   = UIP_HTONS(LOCAL_SERVER_PORT);
  server_ep.secure = 1;

  /* Brief settle so setest is listening and the route is fresh. */
  etimer_set(&et, CLOCK_SECOND * LOCAL_SETTLE_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  LOG_INFO("Connecting to setest [%s]:%u over CoAPS (PSK)\n",
           LOCAL_SERVER_ADDR, (unsigned)LOCAL_SERVER_PORT);
  if(!coap_endpoint_connect(&server_ep)) {
    LOG_ERR("coap_endpoint_connect failed\n");
    PROCESS_EXIT();
  }

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
