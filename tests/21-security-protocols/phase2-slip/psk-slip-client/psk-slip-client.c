/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Phase-2 SLIP-uplink PSK DTLS client for the `setest` server.
 *
 *   Single-board topology (no second radio): this board is its OWN RPL root,
 *   reachable over a SLIP serial link. The host runs
 *       tunslip6 -s <serial> fd00::1/64
 *   which assigns the prefix and bridges the board's IPv6 traffic to a tun
 *   interface; the `setest` PSK server (scenario "psk") listens at the host
 *   tun endpoint fd00::1 on UDP 5686. The board then does a normal CoAPS+PSK
 *   GET /test/hello over that link.
 *
 *   This is the hardware counterpart of psk-native-dtls-client.c (cooja): same
 *   PSK credentials and ciphersuite, but the uplink is real serial SLIP and the
 *   server is the Python setest module rather than a native Contiki server.
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

#include "sys/log.h"
#define LOG_MODULE "PSK-SLIP-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef PHASE2_SERVER_ADDR
#define PHASE2_SERVER_ADDR "fd00::1"
#endif
#ifndef PHASE2_SERVER_PORT
#define PHASE2_SERVER_PORT  5686       /* setest scenario "psk" */
#endif
#ifndef PHASE2_CONNECT_DELAY_S
#define PHASE2_CONNECT_DELAY_S 5
#endif
#define HANDSHAKE_TIMEOUT_S 120

/* Set by the embedded RPL border-router (rpl-border-router.c) once tunslip6
 * has sent the prefix and the board has become the DAG root. */
extern uint8_t prefix_set;

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
  LOG_INFO("=== PHASE2 PSK SLIP test PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(psk_slip_client, "Phase-2 SLIP PSK DTLS Client");
AUTOSTART_PROCESSES(&psk_slip_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(psk_slip_client, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;
  static int ticks;

  PROCESS_BEGIN();

  LOG_INFO("Starting Phase-2 SLIP PSK DTLS client\n");

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

  /* Target the fixed setest host endpoint (NOT the DAG root, which is us). */
  if(!uiplib_ipaddrconv(PHASE2_SERVER_ADDR, &server_ep.ipaddr)) {
    LOG_ERR("Invalid PHASE2_SERVER_ADDR '%s'\n", PHASE2_SERVER_ADDR);
    PROCESS_EXIT();
  }
  server_ep.port   = UIP_HTONS(PHASE2_SERVER_PORT);
  server_ep.secure = 1;

  /* Brief settle so setest is listening. */
  etimer_set(&et, CLOCK_SECOND * PHASE2_CONNECT_DELAY_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  LOG_INFO("Connecting to setest [%s]:%u over CoAPS (PSK)\n",
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
  LOG_INFO("DTLS PSK handshake complete\n");

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "test/hello");
  LOG_INFO("Sending GET /test/hello\n");
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

  coap_endpoint_disconnect(&server_ep);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
