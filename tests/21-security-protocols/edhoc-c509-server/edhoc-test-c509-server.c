/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *   EDHOC test server with C509 c5t credential (hash-by-reference).
 *
 *   SECURITY NOTICE: Test credentials only. Not for production use.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "contiki.h"
#include "contiki-lib.h"
#include "contiki-net.h"
#include "edhoc-exporter.h"
#include "edhoc-server.h"
#include "edhoc-error.h"
#include "edhoc-cred-c509-test.h"

#include "sys/log.h"
#define LOG_MODULE "EDHOCc509Server"
#define LOG_LEVEL LOG_LEVEL_EDHOC

/******************************************************************************/
PROCESS(edhoc_c509_test_server, "EDHOC C509 Test Server");
AUTOSTART_PROCESSES(&edhoc_c509_test_server);
/******************************************************************************/
PROCESS_THREAD(edhoc_c509_test_server, ev, data)
{
  PROCESS_BEGIN();

  if(IS_NETWORK_ROUTING_ROOT) {
    NETSTACK_ROUTING.root_start();
  } else {
    static struct etimer timer;
    etimer_set(&timer, CLOCK_SECOND * 5);
    while(1) {
      if(NETSTACK_ROUTING.node_is_reachable()) {
        LOG_INFO("Network reached!\n");
        break;
      }
      LOG_INFO("Waiting for network...\n");
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
      etimer_reset(&timer);
    }
  }

  /* Own key (responder) — attach cert pointer */
  static cose_key_t server_key;
  memcpy(&server_key, &auth_c509_server_template, sizeof(cose_key_t));
  c509_test_attach_cert(&server_key);

  /* Peer key (initiator) — zero private key, attach cert */
  static cose_key_t client_key;
  memcpy(&client_key, &auth_c509_client_template, sizeof(cose_key_t));
  memset(client_key.ecc.priv, 0, sizeof(client_key.ecc.priv));
  c509_test_attach_cert(&client_key);

  edhoc_error_t result = edhoc_setup_key_pair(&server_key, &client_key,
                                               "Server", "Client");
  if(result != EDHOC_SUCCESS) {
    LOG_ERR("Failed to set up key pair: %s\n", edhoc_error_string(result));
    PROCESS_EXIT();
  }

  LOG_INFO("C509 c5t server ready, cert: %zu bytes\n", sizeof(c509_test_cert));
  edhoc_print_key_info(&server_key, "Server");

  edhoc_server_init();
  if(!edhoc_server_start()) {
    LOG_ERR("Failed to start EDHOC server\n");
    PROCESS_EXIT();
  }

  while(1) {
    PROCESS_WAIT_EVENT();
    int8_t res = edhoc_server_callback(ev, data);
    if(res == SERV_HANDSHAKE_COMPLETE) {
      LOG_INFO("EDHOC handshake completed\n");
      oscore_ctx_t osc;
      int8_t export_result = edhoc_exporter_oscore(&osc, edhoc_ctx);
      if(export_result < 0) {
        LOG_ERR("Failed to export OSCORE context: error code %d\n",
                export_result);
      } else {
        print_oscore_ctx(&osc);
      }
      res = SERV_HANDSHAKE_RESET;
    }
    if(res == SERV_HANDSHAKE_RESET) {
      if(!edhoc_server_reset_handshake()) {
        LOG_ERR("Failed to reset EDHOC server handshake state\n");
        PROCESS_EXIT();
      }
      LOG_INFO("Server handshake state reset\n");
    }
    if(res < 0 && res != SERV_HANDSHAKE_RESET && res != SERV_HANDSHAKE_COMPLETE) {
      LOG_ERR("EDHOC server callback error: error code %d\n", res);
    }
  }
  PROCESS_END();
}
/******************************************************************************/
