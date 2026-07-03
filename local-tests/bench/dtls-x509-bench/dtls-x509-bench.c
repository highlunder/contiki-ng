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
#include "bench-stats.h"

#include "sys/log.h"
#define LOG_MODULE "3-dtls-x509"
#ifdef BENCH_DEBUG
#define LOG_LEVEL  LOG_LEVEL_INFO
#define BENCH_DBG  1
#else
#define LOG_LEVEL  LOG_LEVEL_WARN
#define BENCH_DBG  0
#endif
#ifndef BENCH_LABEL
#define BENCH_LABEL "dtls"
#endif
#ifndef BENCH_SETTLE_S
#define BENCH_SETTLE_S 3
#endif

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
  static struct etimer et, settle;
  static int ticks, iter;
  static rtimer_clock_t t0, t1;
  static bench_stats_t stats;
  static bool ok;

  PROCESS_BEGIN();

  printf("[BENCH] label=%s iters=%d (timing = DTLS handshake connect->connected)\n",
         BENCH_LABEL, BENCH_ITERS);

  coap_engine_init();
  coap_set_keystore(&client_keystore);

  etimer_set(&et, CLOCK_SECOND);
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
  }
  /* Joined the DODAG -- always printed (not log-gated) before timing starts. */
  printf("[BENCH] connected: joined DODAG, hops=%d -- starting %s (%d iters)\n",
         bench_rpl_hops(), BENCH_LABEL, BENCH_ITERS);

  if(!uiplib_ipaddrconv(LOCAL_SERVER_ADDR, &server_ep.ipaddr)) {
    LOG_ERR("Invalid LOCAL_SERVER_ADDR '%s'\n", LOCAL_SERVER_ADDR);
    PROCESS_EXIT();
  }
  server_ep.port   = UIP_HTONS(LOCAL_SERVER_PORT);
  server_ep.secure = 1;

  etimer_set(&et, CLOCK_SECOND * LOCAL_SETTLE_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  bench_stats_init(&stats);

  for(iter = 0; iter < BENCH_ITERS; iter++) {
    /* Recover: ensure the route is up before each iteration (RPL churn /
     * a prior failure may have dropped it). */
    while(!NETSTACK_ROUTING.node_is_reachable()) {
      etimer_set(&et, CLOCK_SECOND * 2);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }
    /* --- timed DTLS handshake: connect() -> is_connected --- */
    ok = false;
    t0 = bench_time_now();
    if(coap_endpoint_connect(&server_ep)) {
      etimer_set(&et, CLOCK_SECOND);
      ticks = 0;
      while(!coap_endpoint_is_connected(&server_ep)) {
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
        etimer_reset(&et);
        if(++ticks >= BENCH_HS_DEADLINE_S) { break; }
      }
      if(coap_endpoint_is_connected(&server_ep)) {
        t1 = bench_time_now();
        ok = true;
      }
    }

    if(ok) {
      /* retx=0: DTLS flight retransmits are not exposed by mbedtls-support. */
      bench_stats_add_us(&stats, bench_elapsed_us(t0, t1), 0);
      /* Complete the cycle with one CoAP GET (untimed) to verify + keep the
       * server exchange sane. */
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, "test/hello");
      COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);
    } else {
      bench_stats_add_fail(&stats);
    }

    coap_endpoint_disconnect(&server_ep);
    bench_stats_print(BENCH_LABEL, &stats, bench_rpl_hops(), BENCH_DBG);

    etimer_set(&settle,
               CLOCK_SECOND * (ok ? BENCH_SETTLE_S : BENCH_FAIL_SETTLE_S));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&settle));
  }

  printf("=== BENCH %s DONE: %lu ok / %lu fail of %d ===\n",
         BENCH_LABEL, (unsigned long)stats.n, (unsigned long)stats.fail,
         BENCH_ITERS);
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
