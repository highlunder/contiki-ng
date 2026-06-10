/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden.
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
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         CoAPS client for mixed-architecture testing in cooja-ng.
 *
 *         Targets a cooja native (x86) server at node_id=1.  The cooja
 *         platform derives the link-layer address from node_id as:
 *           { 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00 }  (node_id=1)
 *         → EUI-64 interface ID (U/L bit set): 03:00:01:00:01:00:01:00
 *         → link-local: fe80::0300:0100:0100:0100
 *
 *         Counterpart of c509-hw-test/c509-server.cooja (TARGET=cooja).
 *         Used with cooja-ng configs/c509-dtls-mixed.json.
 * \author
 *         Joel Hoglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "net/ipv6/uiplib.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "coap-keystore.h"
#include "mbedtls-support/mbedtls-support.h"
#include "../c509-credentials.h"

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "C509 Client"
#define LOG_LEVEL  LOG_LEVEL_INFO
/*---------------------------------------------------------------------------*/
/*
 * Delay before initiating the DTLS connection.  Allows the IPv6 stack to
 * complete DAD and the server to finish its own DTLS setup.
 */
#define CONNECT_DELAY_S    10
/*
 * On x86 cooja the ECDSA operations complete in microseconds; 30 s is
 * generous.  On nRF52840 the same operations take ~3 s each, so the
 * nRF52840 client uses 120 s.
 */
#define HANDSHAKE_TIMEOUT_S 30
/*---------------------------------------------------------------------------*/
static int
get_c509_info(const coap_endpoint_t *ep, coap_keystore_c509_entry_t *info)
{
  info->ca_cert = test_c509_cert;
  info->ca_cert_len = sizeof(test_c509_cert);
  info->own_cert = test_c509_cert;
  info->own_cert_len = sizeof(test_c509_cert);
  info->priv_key = test_priv_key;
  info->priv_key_len = sizeof(test_priv_key);
  return 1;
}

static const coap_keystore_t client_keystore = {
  .coap_get_psk_info = NULL,
  .coap_get_cert_info = NULL,
  .coap_get_c509_info = get_c509_info,
};
/*---------------------------------------------------------------------------*/
static coap_endpoint_t server_ep;
/*---------------------------------------------------------------------------*/
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
}
/*---------------------------------------------------------------------------*/
PROCESS(c509_client_process, "C509 CoAPS Client (mixed)");
AUTOSTART_PROCESSES(&c509_client_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(c509_client_process, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;

  PROCESS_BEGIN();

  LOG_INFO("Starting C509 CoAPS client (cooja-server target)\n");

  coap_engine_init();
  coap_set_keystore(&client_keystore);

  /*
   * Cooja native node_id=1 link-local address.
   * Derived from link-layer 0001.0001.0001.0001 (observed at runtime):
   *   bytes 00:01:00:01:00:01:00:01 → U/L bit set on byte 0 → 02:01:00:01:00:01:00:01
   *   → interface ID 0201:0001:0001:0001 → link-local fe80::201:1:1:1
   */
  uiplib_ipaddrconv("fe80::201:1:1:1", &server_ep.ipaddr);
  server_ep.port = UIP_HTONS(COAP_DEFAULT_SECURE_PORT);
  server_ep.secure = 1;

  /* Wait for network stack to settle before opening the DTLS session. */
  etimer_set(&et, CLOCK_SECOND * CONNECT_DELAY_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  LOG_INFO("Connecting to server at fe80::201:1:1:1 (CoAPS)\n");
  if(!coap_endpoint_connect(&server_ep)) {
    LOG_ERR("coap_endpoint_connect failed\n");
    PROCESS_EXIT();
  }

  /* Poll every second until the DTLS handshake completes or times out. */
  etimer_set(&et, CLOCK_SECOND);
  {
    static int handshake_ticks;
    handshake_ticks = 0;
    while(!coap_endpoint_is_connected(&server_ep)) {
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
      etimer_reset(&et);
      if(++handshake_ticks >= HANDSHAKE_TIMEOUT_S) {
        LOG_ERR("DTLS handshake timed out\n");
        PROCESS_EXIT();
      }
    }
  }
  LOG_INFO("DTLS connected\n");

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "test/hello");
  LOG_INFO("Sending GET /test/hello\n");
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

  LOG_INFO("Request complete\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
