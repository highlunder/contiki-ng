/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Rung 4: DTLS + C509 (Type-2) over the air, against setest scenario "B2"
 *   (UDP 5687).
 *
 *   Plain RPL node: joins the Firefly DAG, then does a C509 (natively-CBOR-
 *   signed, Type-2) DTLS handshake to setest at fd00::1 using the in-handshake
 *   verify path, and a CoAP GET /test/hello. Radio counterpart of
 *   phase2-slip/c509-slip-client.c.
 *
 *   INTEROP NOTE: this board presents a CA-issued Type-2 C509 and verifies the
 *   peer with a CBOR-domain custom callback. setest's stock B2 serves a
 *   *self-signed* Type-2; full interop with this CA-issued Type-2 client needs
 *   the setest out-of-band / patched-mbedTLS verifier (PLAN-c509-type2-dtls.md,
 *   Task 10). Until then this rung exercises the C509 credential + network path
 *   over the air but may not complete the handshake against the current B2.
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
#include "edhoc-cred-c509-native-test.h"
#include "bench-stats.h"

#include "sys/log.h"
#define LOG_MODULE "4-dtls-c509"
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
#define LOCAL_SERVER_PORT 5687        /* setest scenario "B2" (Type-2) */
#endif
#ifndef LOCAL_SETTLE_S
#define LOCAL_SETTLE_S 5
#endif
#define HANDSHAKE_TIMEOUT_S 120

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
  LOG_INFO("=== 4-dtls-c509 PASSED ===\n");
}

/*---------------------------------------------------------------------------*/
PROCESS(dtls_c509_test, "4-dtls-c509 (OTA)");
AUTOSTART_PROCESSES(&dtls_c509_test);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(dtls_c509_test, ev, data)
{
  static coap_message_t request[1];
  static struct etimer et, settle;
  static int ticks, iter;
  static rtimer_clock_t t0, t1;
  static bench_stats_t stats;
  static bool ok;

  PROCESS_BEGIN();

  /* Assemble the CA public key (x||y) once for the C509 in-handshake verify. */
  memcpy(s_ca_pub_xy,      s_ca_pub_x, 32);
  memcpy(s_ca_pub_xy + 32, s_ca_pub_y, 32);

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
