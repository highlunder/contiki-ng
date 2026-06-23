/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Phase-2 SLIP-uplink X.509 DTLS client for the `setest` server (scenario A).
 *
 *   Single-board topology (no second radio): this board is its own RPL root
 *   over a SLIP serial link (host runs `tunslip6 -s <serial> fd00::1/64`); the
 *   setest scenario-A server listens at the host tun endpoint fd00::1 on UDP
 *   5684. The board does a mutually-authenticated X.509 DTLS handshake and a
 *   CoAP GET /test/hello.
 *
 *   Hardware counterpart of x509-native-dtls-client.c (cooja), reduced to a
 *   single handshake (the §5.3.7 resumption sub-test is out of scope here).
 *
 *   CREDENTIAL ALIGNMENT: this uses the board's edhoc-cred-x509-native-test.h
 *   certificates. setest scenario A must present/trust a chain under the SAME
 *   CA for mutual auth to succeed — verify/align on first hardware bring-up
 *   (see PHASE2-SLIP-README.md). PSK (psk-slip-client) has no such dependency.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/ipv6/uiplib.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "coap-keystore.h"
#include "edhoc-cred-x509-native-test.h"

#include "sys/log.h"
#define LOG_MODULE "X509-SLIP-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef PHASE2_SERVER_ADDR
#define PHASE2_SERVER_ADDR "fd00::1"
#endif
#ifndef PHASE2_SERVER_PORT
#define PHASE2_SERVER_PORT  5684       /* setest scenario "A" */
#endif
#ifndef PHASE2_CONNECT_DELAY_S
#define PHASE2_CONNECT_DELAY_S 5
#endif
#define HANDSHAKE_TIMEOUT_S 120

/* Set by the embedded RPL border-router once tunslip6 sends the prefix. */
extern uint8_t prefix_set;

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
  LOG_INFO("=== PHASE2 X.509 SLIP test PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(x509_slip_client, "Phase-2 SLIP X.509 DTLS Client");
AUTOSTART_PROCESSES(&x509_slip_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(x509_slip_client, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;
  static int ticks;

  PROCESS_BEGIN();

  LOG_INFO("Starting Phase-2 SLIP X.509 DTLS client\n");

  coap_engine_init();
  coap_set_keystore(&client_keystore);

  /* Wait for the embedded border-router to receive its prefix over SLIP. */
  etimer_set(&et, CLOCK_SECOND);
  while(!prefix_set) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
    LOG_INFO("Waiting for SLIP prefix from tunslip6...\n");
  }
  LOG_INFO("SLIP prefix set; network up\n");

  if(!uiplib_ipaddrconv(PHASE2_SERVER_ADDR, &server_ep.ipaddr)) {
    LOG_ERR("Invalid PHASE2_SERVER_ADDR '%s'\n", PHASE2_SERVER_ADDR);
    PROCESS_EXIT();
  }
  server_ep.port   = UIP_HTONS(PHASE2_SERVER_PORT);
  server_ep.secure = 1;

  etimer_set(&et, CLOCK_SECOND * PHASE2_CONNECT_DELAY_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  LOG_INFO("Connecting to setest [%s]:%u over CoAPS (X.509)\n",
           PHASE2_SERVER_ADDR, (unsigned)PHASE2_SERVER_PORT);
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
