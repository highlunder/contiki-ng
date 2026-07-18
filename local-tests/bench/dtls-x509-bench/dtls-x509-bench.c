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

/* --- Cert-over-CSMA reliability overrides (before bench-stats.h so its #ifndef
 * defaults don't win). A mutual-auth cert handshake floods the single CSMA hop
 * with ~22 6LoWPAN fragments and spikes link ETX; the DTLS layer recovers a lost
 * flight only via its own retransmission, whose MIN timeout is 9 s (mbedtls-support
 * COAP_MBEDTLS_HANDSHAKE_MIN_TIMEOUT_MS), doubling to ~9 s, ~27 s, ~63 s. The old
 * 15 s deadline allowed exactly ONE retransmit, cutting the handshake off right
 * before the 2nd would land -> spurious fail -> the failed attempt re-floods the
 * hop -> congestion collapse into back-to-back fails. Give the DTLS retransmission
 * room (40 s spans the 9 s + 27 s retries) and a long post-fail cooldown.
 * NOTE: an earlier "wait until rank decays to <=1 hop" adaptive settle was
 * REMOVED -- measured runs show cert handshakes complete fine at hops=2..6 (the
 * 40 s deadline lets the DTLS retransmit land), so gating on rank only added a
 * 60 s cap wait per inflated iteration (the ~78 s gaps) with no reliability gain;
 * the real fails were all at hops=1 or parent-loss, which this does not touch. */
#define BENCH_HS_DEADLINE_S 40
#define BENCH_FAIL_SETTLE_S 30

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
/* Cert DTLS sends ~22 6LoWPAN fragments per handshake (full chain BOTH ways). At
 * 5 s settle the back-to-back bursts saturate the single CSMA link, so the link
 * ETX never decays -> RPL rank inflates (misreported as high `hops`, see
 * bench-stats.h) and the parent is occasionally lost on freshness -> multi-second
 * stalls. 15 s lets ETX decay between handshakes. Override with -DBENCH_SETTLE_S=.
 * (PSK stays at 5 s -- it is only a handful of frames.) */
#ifndef BENCH_SETTLE_S
#define BENCH_SETTLE_S 15
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
/* Set by response_handler on a real (non-NULL) response; the loop reads it so a
 * post-handshake GET timeout is counted as a failed iteration, not swallowed. */
static volatile bool got_response;

static void
response_handler(coap_message_t *response)
{
  if(response == NULL) {
    LOG_ERR("Request timed out\n");
    return;
  }
  got_response = true;
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
  static struct etimer et, settle, hs_deadline;
  static int iter;
  static rtimer_clock_t t0, t1, rep0;
  static bool was_down;
  static bench_stats_t stats;
  static uint32_t bench_samples[BENCH_ITERS];  /* successful durations (us) */
  static bool ok;

  PROCESS_BEGIN();

  bench_print_fw_build(NULL);
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

#ifdef BENCH_SERVER_IS_ROOT
  /* The DTLS server is the RPL root itself (Contiki x509-native-dtls-server on a
   * 2-node TSCH setup / cooja-ng emulator), not a host behind a border router.
   * Resolve it dynamically -- its address is FICR-derived per node, so it can't be
   * hardcoded. Build with -DBENCH_SERVER_IS_ROOT for that topology; the default
   * (below) targets LOCAL_SERVER_ADDR = the setest host at fd00::1 behind the BR. */
  {
    uip_ipaddr_t root_addr;
    while(!NETSTACK_ROUTING.get_root_ipaddr(&root_addr)) {
      etimer_set(&et, CLOCK_SECOND);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }
    uip_ipaddr_copy(&server_ep.ipaddr, &root_addr);
  }
#else
  if(!uiplib_ipaddrconv(LOCAL_SERVER_ADDR, &server_ep.ipaddr)) {
    LOG_ERR("Invalid LOCAL_SERVER_ADDR '%s'\n", LOCAL_SERVER_ADDR);
    PROCESS_EXIT();
  }
#endif
  server_ep.port   = UIP_HTONS(LOCAL_SERVER_PORT);
  server_ep.secure = 1;

  etimer_set(&et, CLOCK_SECOND * LOCAL_SETTLE_S);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  bench_stats_init(&stats);

  for(iter = 0; iter < BENCH_ITERS; iter++) {
    /* Recover: ensure the route is up before each iteration (RPL churn /
     * a prior failure may have dropped it). Time any DODAG repair we wait
     * through, so a slow repair is recorded (rpl_rep_ms), not invisible. */
    bench_stats_repair_reset_last(&stats);
    rep0 = bench_time_now();
    was_down = false;
    while(!NETSTACK_ROUTING.node_is_reachable()) {
      was_down = true;
      etimer_set(&et, CLOCK_SECOND * 2);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }
    if(was_down) {
      bench_stats_add_repair(&stats, bench_elapsed_us(rep0, bench_time_now()));
    }
    /* --- timed DTLS handshake: connect() -> is_connected --- */
    ok = false;
    t0 = bench_time_now();
    if(coap_endpoint_connect(&server_ep)) {
      /* Poll is_connected finely so t1 lands close to actual completion (the old
       * 1 s poll quantized every handshake to ~1000 ms); a separate deadline
       * etimer bounds the whole wait independently of the poll period. */
      etimer_set(&hs_deadline, CLOCK_SECOND * BENCH_HS_DEADLINE_S);
      etimer_set(&et, BENCH_HS_POLL_TICKS);
      while(!coap_endpoint_is_connected(&server_ep)) {
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et) || etimer_expired(&hs_deadline));
        if(etimer_expired(&hs_deadline)) { break; }
        etimer_reset(&et);
      }
      if(coap_endpoint_is_connected(&server_ep)) {
        t1 = bench_time_now();
        ok = true;
      }
    }

    if(ok) {
      /* The DTLS handshake completed -> record its latency (retx=0: DTLS flight
       * retransmits are not exposed by mbedtls-support). t0/t1 are static, so
       * compute+use dur_us BEFORE the GET (which yields). Then one CoAP GET
       * verifies the session; on a lossy/slotted link its response can be lost
       * though the handshake was fine, so a GET timeout only bumps get_fail
       * (visible) WITHOUT discarding the valid handshake sample. */
      uint32_t dur_us = bench_elapsed_us(t0, t1);
      bench_samples[stats.n] = dur_us;
      bench_stats_add_us(&stats, dur_us, 0);
      got_response = false;
      coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
      coap_set_header_uri_path(request, "test/hello");
      COAP_BLOCKING_REQUEST(&server_ep, request, response_handler);
      if(!got_response) {
        bench_stats_add_get_fail(&stats);
      }
    } else {
      bench_stats_add_fail(&stats);
    }

    coap_endpoint_disconnect(&server_ep);
    bench_stats_print(BENCH_LABEL, &stats, bench_rpl_hops(), BENCH_DBG);

    /* Cooldown between iterations (longer after a fail) so the single CSMA hop's
     * ETX drains before the next cert flight. Untimed (outside the measured
     * region). Fixed, not adaptive -- see the note on the overrides above. */
    etimer_set(&settle,
               CLOCK_SECOND * (ok ? BENCH_SETTLE_S : BENCH_FAIL_SETTLE_S));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&settle));
  }

  printf("=== BENCH %s DONE: %lu ok / %lu fail of %d ===\n",
         BENCH_LABEL, (unsigned long)stats.n, (unsigned long)stats.fail,
         BENCH_ITERS);
  /* Repeat the build stamp with the result so a pasted block is self-identifying. */
  bench_print_fw_build(NULL);
  /* Robust final summary (median + p95) -- copy this line as the result. */
  bench_stats_print_final(BENCH_LABEL, &stats, bench_samples,
                          bench_rpl_hops(), BENCH_DBG);
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
