/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Rung 3: DTLS + X.509 over the air, against setest scenario "A" (UDP 5684).
 *
 *   Plain RPL node: joins the Firefly DAG, then does a mutually-authenticated
 *   X.509 DTLS handshake to setest at fd00::1 and a CoAP GET /test/hello.
 *   Radio counterpart of phase2-slip/x509-slip-client.c.
 *
 *   CREDENTIAL ALIGNMENT: uses edhoc-cred-x509-native-test.h; setest scenario A
 *   must present/trust a chain under the SAME CA for mutual auth to succeed.
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
#include "edhoc-cred-x509-native-test.h"
#include "local-test-banner.h"

#include "sys/log.h"
#define LOG_MODULE "3-dtls-x509"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef LOCAL_SERVER_ADDR
#define LOCAL_SERVER_ADDR "fd00::1"
#endif
#ifndef LOCAL_SERVER_PORT
#define LOCAL_SERVER_PORT 5684        /* setest scenario "A" */
#endif
#ifndef LOCAL_SETTLE_S
#define LOCAL_SETTLE_S 5
#endif
#define HANDSHAKE_TIMEOUT_S 120

/*---------------------------------------------------------------------------*/
static int
get_cert_info(const coap_endpoint_t *ep, coap_keystore_cert_entry_t *info)
{
  info->ca_cert      = x509_native_ca_cert;
  info->ca_cert_len  = sizeof(x509_native_ca_cert);
  info->own_cert     = x509_native_client_cert;
  info->own_cert_len = sizeof(x509_native_client_cert);
  info->priv_key     = x509_native_client_priv_key_der;
  info->priv_key_len = sizeof(x509_native_client_priv_key_der);
  return 1;
}

static const coap_keystore_t client_keystore = {
  .coap_get_psk_info  = NULL,
  .coap_get_cert_info = get_cert_info,
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
  LOG_INFO("=== 3-dtls-x509 PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(dtls_x509_test, "3-dtls-x509 (OTA)");
AUTOSTART_PROCESSES(&dtls_x509_test);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_x509_test, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;
  static int ticks;

  PROCESS_BEGIN();

  local_test_banner("3-dtls-x509", LOCAL_SERVER_ADDR, LOCAL_SERVER_PORT);

  coap_engine_init();
  coap_set_keystore(&client_keystore);

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

  etimer_set(&et, CLOCK_SECOND * LOCAL_SETTLE_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  LOG_INFO("Connecting to setest [%s]:%u over CoAPS (X.509)\n",
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
  LOG_INFO("DTLS X.509 handshake complete\n");

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "test/hello");
  LOG_INFO("Sending GET /test/hello\n");
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

  coap_endpoint_disconnect(&server_ep);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
