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
 *         CoAPS client for the cross-platform test:
 *         emulated nRF52840 → 802.15.4 → slip-radio → border-router → Linux
 *
 *         The server is native-server.native running on the Linux host.
 *         It creates tun0 with prefix fd01::/64 and CONTIKI_NODE_ID=1,
 *         giving it global address fd01::302:304:506:1.
 *
 *         This client reaches the server via:
 *           802.15.4 mesh → slip-radio (cooja node 1) → SLIP/TCP:60001
 *           → border-router.native → tun1 (fd00::/64)
 *           → Linux IPv6 kernel routing → tun0 → native-server
 *
 *         The client uses a long initial delay (30s) to allow RPL to form
 *         and assign a global fd00:: address before connecting.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "net/ipv6/uiplib.h"
#include "net/routing/routing.h"
#include "net/ipv6/uip-ds6.h"
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
 * Wait for RPL to form a route before attempting to connect.
 * Override in project-conf.h for topologies with more hops (longer convergence).
 * 60 s is sufficient for 1-hop; use 120 s+ for 3-hop chains.
 */
#ifndef CONNECT_DELAY_S
#define CONNECT_DELAY_S     60
#endif
/*
 * Timeout waiting for the DTLS handshake.  secp256r1 on nRF52840 takes ~3 s
 * per operation; the full handshake takes ~9 s.  Allow 120 s headroom.
 */
#ifndef HANDSHAKE_TIMEOUT_S
#define HANDSHAKE_TIMEOUT_S 120
#endif
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
PROCESS(c509_client_process, "C509 CoAPS Client (border-router path)");
AUTOSTART_PROCESSES(&c509_client_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(c509_client_process, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et;

  PROCESS_BEGIN();

  LOG_INFO("Starting C509 CoAPS client (border-router path)\n");
  LOG_INFO("Server: fd01::302:304:506:1 (native-server via RPL mesh)\n");

  coap_engine_init();
  coap_set_keystore(&client_keystore);

  /*
   * Server is native-server.native on the Linux host.
   * Address: CONTIKI_NODE_ID=1 + prefix fd01::/64
   *   → EUI-64 from link-layer 0102.0304.0506.0001
   *   → fd01::302:304:506:1
   */
  uiplib_ipaddrconv("fd01::302:304:506:1", &server_ep.ipaddr);
  server_ep.port = UIP_HTONS(COAP_DEFAULT_SECURE_PORT);
  server_ep.secure = 1;

  /* Wait for RPL to form and assign a global address. */
  LOG_INFO("Waiting %ds for RPL convergence...\n", CONNECT_DELAY_S);
  etimer_set(&et, CLOCK_SECOND * CONNECT_DELAY_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  /* Log our global address (if any) before connecting. */
  {
    uip_ds6_addr_t *addr = uip_ds6_get_global(ADDR_PREFERRED);
    if(addr) {
      LOG_INFO("Global addr: ");
      LOG_INFO_6ADDR(&addr->ipaddr);
      LOG_INFO_("\n");
    } else {
      LOG_WARN("No global addr yet — connecting anyway\n");
    }
  }

  LOG_INFO("Connecting to server (CoAPS)\n");
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

  /* Brief settling delay: the DTLS Finished flight leaves the 3-hop mesh
   * saturated with ACKs and retransmissions for a few seconds.  Waiting
   * here lets the channel drain before the CoAP GET competes for it. */
#ifndef POST_HANDSHAKE_SETTLE_S
#define POST_HANDSHAKE_SETTLE_S 8
#endif
  etimer_set(&et, CLOCK_SECOND * POST_HANDSHAKE_SETTLE_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
  coap_set_header_uri_path(request, "test/hello");
  LOG_INFO("Sending GET /test/hello\n");
  COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);

  LOG_INFO("Request complete\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
