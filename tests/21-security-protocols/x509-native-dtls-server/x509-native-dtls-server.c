/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   CoAPS server for plain X.509 DTLS test (Cooja, native target).
 *
 *   Scenario A of the C509 lossy-radio sweep (PLAN-c509-lice-followup.md
 *   sec. 5.3.5): standard mbedTLS COAP_DTLS_SEC_MODE_CERT path with raw
 *   X.509 DER certs/keys, over the same P-256 keypairs as the C509 native
 *   chain, for an apples-to-apples size comparison against scenarios
 *   B/C/D.
 *
 *   Exposes GET /test/hello over DTLS.  Logs a pass string for each
 *   request served -- the client (x509-native-dtls-client) issues two
 *   GETs over two separate DTLS connections (full handshake, then a
 *   resumed handshake) as part of the §5.3.7 session-resumption
 *   experiment (PLAN-c509-lice-followup.md sec. 5.3.7).
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#if MAC_CONF_WITH_TSCH
#include "net/mac/tsch/tsch.h"     /* the root must also be the TSCH coordinator */
#endif
#include "coap-engine.h"
#include "coap-keystore.h"
#include "mbedtls-support/mbedtls-support.h"
#include "edhoc-cred-x509-native-test.h"

#include "sys/log.h"
#define LOG_MODULE "X509-Nat-Sv"
#define LOG_LEVEL  LOG_LEVEL_INFO

static int requests_served = 0;

/*---------------------------------------------------------------------------*/
static void
res_get_handler(coap_message_t *request, coap_message_t *response,
                uint8_t *buffer, uint16_t preferred_size, int32_t *offset)
{
  static const char msg[] = "Hello from native X.509 server!";

  LOG_INFO("GET /test/hello\n");
  memcpy(buffer, msg, sizeof(msg) - 1);
  coap_set_header_content_format(response, TEXT_PLAIN);
  coap_set_payload(response, buffer, sizeof(msg) - 1);

  requests_served++;
  LOG_INFO("=== Native X.509 DTLS server exchange complete (request %d) ===\n",
           requests_served);
}

RESOURCE(res_hello,
         "title=\"Native X.509 Hello\";rt=\"Text\"",
         res_get_handler, NULL, NULL, NULL);

/*---------------------------------------------------------------------------*/
#ifdef DTLS_BIG_FLIGHT
/* Test variant: present leaf + CA as a 2-cert chain (~700 B of certs) so the
 * server's Certificate flight datagram exceeds the hardware setest server's
 * ~848 B single record -- to check whether the client's large-datagram
 * TSCH-receive failure (seen only on hardware) has a SIZE threshold the
 * emulator can hit, or is purely hardware timing. */
static uint8_t big_chain[sizeof(x509_native_server_cert) +
                         sizeof(x509_native_ca_cert)];
#endif

static int
get_cert_info(const coap_endpoint_t *ep, coap_keystore_cert_entry_t *info)
{
  info->ca_cert      = x509_native_ca_cert;
  info->ca_cert_len  = sizeof(x509_native_ca_cert);
#ifdef DTLS_BIG_FLIGHT
  memcpy(big_chain, x509_native_server_cert, sizeof(x509_native_server_cert));
  memcpy(big_chain + sizeof(x509_native_server_cert),
         x509_native_ca_cert, sizeof(x509_native_ca_cert));
  info->own_cert     = big_chain;
  info->own_cert_len = sizeof(big_chain);
#else
  info->own_cert     = x509_native_server_cert;
  info->own_cert_len = sizeof(x509_native_server_cert);
#endif
  info->priv_key     = x509_native_server_priv_key_der;
  info->priv_key_len = sizeof(x509_native_server_priv_key_der);
  return 1;
}

static const coap_keystore_t server_keystore = {
  .coap_get_psk_info  = NULL,
  .coap_get_cert_info = get_cert_info,
  .coap_get_c509_info = NULL,
};

/*---------------------------------------------------------------------------*/
PROCESS(x509_native_dtls_server, "Native X.509 DTLS Server");
AUTOSTART_PROCESSES(&x509_native_dtls_server);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(x509_native_dtls_server, ev, data)
{
  PROCESS_BEGIN();

#if MAC_CONF_WITH_TSCH
  /* The DTLS server is the RPL root (IS_NETWORK_ROUTING_ROOT); on TSCH it must
   * also start the network as coordinator, else no node can associate. */
  if(IS_NETWORK_ROUTING_ROOT) {
    tsch_set_coordinator(1);
  }
#endif

  if(IS_NETWORK_ROUTING_ROOT) {
    NETSTACK_ROUTING.root_start();
  }

  LOG_INFO("Starting native X.509 DTLS server\n");

  coap_set_keystore(&server_keystore);
  coap_engine_init();
  coap_activate_resource(&res_hello, "test/hello");

  if(!coap_secure_server_setup()) {
    LOG_ERR("DTLS server setup failed\n");
    PROCESS_EXIT();
  }
  LOG_INFO("DTLS server ready\n");

  while(1) {
    PROCESS_YIELD();
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
