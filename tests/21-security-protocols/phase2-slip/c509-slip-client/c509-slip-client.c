/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Phase-2 SLIP-uplink C509 (Type-2) DTLS client for the `setest` server.
 *
 *   Single-board topology (no second radio): this board is its own RPL root
 *   over a SLIP serial link (host runs `tunslip6 -s <serial> fd00::1/64`). The
 *   board does a C509 (natively-CBOR-signed, Type-2) DTLS handshake using the
 *   custom in-handshake verify path (c509_native_verify_cb) and a CoAP
 *   GET /test/hello.
 *
 *   Hardware counterpart of c509-native-dtls-client.c (cooja), reduced to a
 *   single handshake.
 *
 *   INTEROP NOTE: the board presents a CA-issued Type-2 C509 and verifies the
 *   peer with a CBOR-domain custom callback. setest's stock python-mbedtls
 *   only serves Type-3 (scenario B, reconstructed X.509) or *self-signed*
 *   Type-2 (scenario B2). Full interop with this CA-issued Type-2 client needs
 *   the setest out-of-band / patched-mbedTLS verifier (PLAN-c509-type2-dtls.md,
 *   Task 10). Until then this firmware is staged but will not complete a
 *   handshake against the current setest B2. See PHASE2-SLIP-README.md.
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
#include "edhoc-cred-c509-native-test.h"

#include "sys/log.h"
#define LOG_MODULE "C509-SLIP-Cl"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef PHASE2_SERVER_ADDR
#define PHASE2_SERVER_ADDR "fd00::1"
#endif
#ifndef PHASE2_SERVER_PORT
#define PHASE2_SERVER_PORT  5687       /* setest scenario "B2" (Type-2) */
#endif
#ifndef PHASE2_CONNECT_DELAY_S
#define PHASE2_CONNECT_DELAY_S 5
#endif
#define HANDSHAKE_TIMEOUT_S 120

/* Set by the embedded RPL border-router once tunslip6 sends the prefix. */
extern uint8_t prefix_set;

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
  if(response == NULL) {
    LOG_ERR("Request timed out\n");
    return;
  }
  const uint8_t *payload;
  int len = coap_get_payload(response, &payload);
  LOG_INFO("Response: %.*s\n", len, (char *)payload);
  LOG_INFO("=== PHASE2 C509 Type-2 SLIP test PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(c509_slip_client, "Phase-2 SLIP C509 DTLS Client");
AUTOSTART_PROCESSES(&c509_slip_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(c509_slip_client, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;
  static int ticks;

  PROCESS_BEGIN();

  memcpy(s_ca_pub_xy,      s_ca_pub_x, 32);
  memcpy(s_ca_pub_xy + 32, s_ca_pub_y, 32);

  LOG_INFO("Starting Phase-2 SLIP C509 (Type-2) DTLS client\n");

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

  LOG_INFO("Connecting to setest [%s]:%u over CoAPS (C509)\n",
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
  LOG_INFO("DTLS C509 handshake complete\n");

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "test/hello");
  LOG_INFO("Sending GET /test/hello\n");
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

  coap_endpoint_disconnect(&server_ep);

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
