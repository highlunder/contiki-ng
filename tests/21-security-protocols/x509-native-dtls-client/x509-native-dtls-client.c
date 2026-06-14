/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   CoAPS client for plain X.509 DTLS test (Cooja, native target).
 *
 *   Scenario A of the C509 lossy-radio sweep (PLAN-c509-lice-followup.md
 *   sec. 5.3.5): standard mbedTLS COAP_DTLS_SEC_MODE_CERT path with raw
 *   X.509 DER certs/keys, over the same P-256 keypairs as the C509 native
 *   chain, for an apples-to-apples size comparison against scenarios
 *   B/C/D.
 *
 *   Waits for RPL to converge, resolves the DAG root address, then opens
 *   a DTLS session to the server (x509-native-dtls-server, node 2) and
 *   issues a CoAP GET /test/hello ("Handshake 1, full").  It then saves
 *   the negotiated DTLS session, disconnects, reconnects and repeats the
 *   GET ("Handshake 2, resumed") -- the §5.3.7 session-resumption
 *   experiment (PLAN-c509-lice-followup.md sec. 5.3.7).  On success logs
 *   the PASS string after each handshake.
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
#include "edhoc-cred-x509-native-test.h"

#include "sys/log.h"
#define LOG_MODULE "X509-Nat-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define CONNECT_DELAY_S    15
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

static int response_count;

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
  response_count++;
  if(response_count == 1) {
    LOG_INFO("=== Native X.509 DTLS test (handshake 1, full) PASSED ===\n");
  } else {
    LOG_INFO("=== Native X.509 DTLS test (handshake 2, resumed) PASSED ===\n");
  }
}

/*---------------------------------------------------------------------------*/
PROCESS(x509_native_dtls_client, "Native X.509 DTLS Client");
AUTOSTART_PROCESSES(&x509_native_dtls_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(x509_native_dtls_client, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;
  static mbedtls_ssl_session saved_session;
  static int handshake_num;
  static int ticks;

  PROCESS_BEGIN();

  LOG_INFO("Starting native X.509 DTLS client\n");

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

  for(handshake_num = 1; handshake_num <= 2; handshake_num++) {
    LOG_INFO("Connecting to server over CoAPS (handshake %d, %s)\n",
             handshake_num, handshake_num == 1 ? "full" : "resumed");
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
    LOG_INFO("DTLS handshake %d complete (%s)\n",
             handshake_num, handshake_num == 1 ? "full" : "resumed");

    coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(request, "test/hello");
    LOG_INFO("Sending GET /test/hello (handshake %d)\n", handshake_num);
    COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

    if(handshake_num == 1) {
      /* Snapshot the negotiated session, then disconnect and stage it
       * for resumption on the next coap_endpoint_connect(). */
      mbedtls_ssl_session_init(&saved_session);
      if(coap_ep_dtls_get_session(&server_ep, &saved_session) != 0) {
        LOG_ERR("coap_ep_dtls_get_session failed\n");
        PROCESS_EXIT();
      }
      coap_endpoint_disconnect(&server_ep);
      coap_ep_dtls_set_resume_session(&saved_session);

      /* Brief delay so the server finishes recycling the session slot. */
      etimer_set(&et, CLOCK_SECOND * 2);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    } else {
      coap_endpoint_disconnect(&server_ep);
      mbedtls_ssl_session_free(&saved_session);
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
