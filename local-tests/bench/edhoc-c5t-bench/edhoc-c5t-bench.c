/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EDHOC + OSCORE end-to-end test client — C509 c5t credentials (Step 1f).
 *
 *   Identical flow to edhoc-oscore-client (KID variant) but uses C509
 *   certificate-hash-by-reference (c5t) for EDHOC authentication:
 *     1. EDHOC handshake (Method 0, c5t credential, cert hashes exchanged)
 *     2. Derive OSCORE security context
 *     3. Send one OSCORE-protected CoAP GET on UDP port OSCORE_UDP_PORT
 *     4. Receive and verify the OSCORE-protected 2.05 Content response
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"    /* NETSTACK_ROUTING.get_root_ipaddr (EDHOC_CONF_SERVER_FROM_ROOT) */
#include "net/ipv6/simple-udp.h"
#include "coap-engine.h"
#include "edhoc-client.h"
#include "edhoc-error.h"
#include "edhoc-exporter.h"
#include "edhoc-cred-c509-test.h"   /* auth_c509_client_template, auth_c509_server_template,
                                        c509_test_attach_cert() */
#include "edhoc-profile.h"          /* opt-in DWT cycle profiling (EDHOC_PROFILE_CYCLES) */
#include "oscore.h"
#include "bench-stats.h"            /* incremental Welford stats + RTIMER timing */

#include "sys/log.h"
#define LOG_MODULE "c5t-bench"
/* Quiet by default: console I/O is slow and blocking, so verbose logging inside
 * the timed handshake would inflate the numbers. Build with -DBENCH_DEBUG=1 to
 * restore INFO logging (also raises LOG_CONF_LEVEL_EDHOC in project-conf.h);
 * either way the BENCH line reports dbg=0/1 so a timing is never mis-read. */
#ifdef BENCH_DEBUG
#define LOG_LEVEL  LOG_LEVEL_INFO
#define BENCH_DBG  1
#else
#define LOG_LEVEL  LOG_LEVEL_WARN
#define BENCH_DBG  0
#endif

/* Benchmark config. BENCH_LABEL identifies the experiment+config in each stats
 * line (the build script sets it, e.g. "edhoc-c5t-cc310-csma"); BENCH_ITERS is
 * in bench-stats.h; BENCH_SETTLE_S is the inter-iteration pause (let the server
 * reset + RPL settle). */
#ifndef BENCH_LABEL
#define BENCH_LABEL "edhoc-c5t"
#endif
#ifndef BENCH_SETTLE_S
#define BENCH_SETTLE_S 5
#endif

#ifndef OSCORE_UDP_PORT
#define OSCORE_UDP_PORT 5686
#endif

/* Firmware build stamp for record-keeping. FW_BUILD_ID is a short date id the
 * Makefile injects (-DFW_BUILD_ID, default below); ECC_BACKEND_NAME names the
 * crypto path (CC310 hardware vs software). Printed at startup alongside the
 * compiler's __DATE__/__TIME__ so any pasted handshake log is self-identifying
 * (which firmware/backend produced the PROFILE timings). Mirrors the
 * cc310-bringup benches. */
#ifndef FW_BUILD_ID
#define FW_BUILD_ID "dev"
#endif
#ifndef ECC_BACKEND_NAME
#define ECC_BACKEND_NAME "software (uECC)"
#endif

#define COAP_CODE_GET     0x01
#define COAP_CODE_CONTENT 0x45

static struct simple_udp_connection oscore_udp;
static oscore_security_context_t client_oscore;
static bool oscore_ready = false;

/* Post-EDHOC OSCORE round-trip recovery: the GET is fire-and-forget UDP, and under
 * loss it can arrive before the server's OSCORE context is ready (ignored) or its
 * response can be lost. Retransmit with a fresh OSCORE PIV until a response,
 * bounded, rather than ending the client after a single send. */
static volatile bool oscore_done = false;
#ifndef OSCORE_GET_MAX_RETX
#define OSCORE_GET_MAX_RETX 6
#endif
#ifndef OSCORE_GET_RETX_T0
#define OSCORE_GET_RETX_T0 (2 * CLOCK_SECOND)
#endif
PROCESS_NAME(edhoc_oscore_c5t_client);

static uint8_t saved_piv[OSCORE_MAX_PIV_LEN];
static uint8_t saved_piv_len;
static uint8_t saved_kid[OSCORE_MAX_ID_LEN];
static uint8_t saved_kid_len;

/*---------------------------------------------------------------------------*/
static void
oscore_response_callback(struct simple_udp_connection *c,
                          const uip_ipaddr_t *source_addr, uint16_t source_port,
                          const uip_ipaddr_t *dest_addr, uint16_t dest_port,
                          const uint8_t *data, uint16_t datalen)
{
  if(!oscore_ready) {
    LOG_WARN("Response arrived before OSCORE context ready — ignored\n");
    return;
  }
  if(datalen < 1 + OSCORE_TAG_LEN + 1) {
    LOG_WARN("Response too short (%u bytes)\n", datalen);
    return;
  }
  uint8_t opt_len = data[0];
  if(opt_len != 0) {
    LOG_WARN("Unexpected non-empty response OSCORE option (len=%u)\n", opt_len);
  }

  const uint8_t *ciphertext = data + 1;
  size_t ciphertext_len = datalen - 1;

  uint8_t plaintext[64];
  size_t plaintext_len = sizeof(plaintext);
  int err = oscore_unprotect_response(&client_oscore,
                                       ciphertext, ciphertext_len,
                                       saved_piv, saved_piv_len,
                                       saved_kid, saved_kid_len,
                                       plaintext, &plaintext_len);
  if(err < 0) {
    LOG_ERR("OSCORE unprotect response failed: %d\n", err);
    return;
  }

  if(plaintext_len < 1) { return; }
  uint8_t code = plaintext[0];
  const uint8_t *payload = NULL;
  size_t payload_len = 0;
  if(plaintext_len > 2 && plaintext[1] == 0xFF) {
    payload = plaintext + 2;
    payload_len = plaintext_len - 2;
  }

  LOG_INFO("OSCORE response OK: code=0x%02x", code);
  if(payload_len > 0) {
    LOG_INFO_(" payload=\"%.*s\"", (int)payload_len, payload);
  }
  LOG_INFO_("\n");

  if(code == COAP_CODE_CONTENT) {
    LOG_INFO("=== EDHOC+OSCORE c5t end-to-end test PASSED ===\n");
    oscore_done = true;
    process_poll(&edhoc_oscore_c5t_client);
  } else {
    LOG_WARN("Unexpected response code 0x%02x\n", code);
  }
}
/*---------------------------------------------------------------------------*/
static void
send_oscore_request(const uip_ipaddr_t *server_addr)
{
  uint8_t inner[1];
  inner[0] = COAP_CODE_GET;

  uint8_t oscore_opt[OSCORE_OPT_MAX_LEN];
  size_t oscore_opt_len = sizeof(oscore_opt);
  uint8_t ciphertext[sizeof(inner) + OSCORE_TAG_LEN];
  size_t ciphertext_len = sizeof(ciphertext);

  int err = oscore_protect_request(&client_oscore,
                                    inner, sizeof(inner),
                                    oscore_opt, &oscore_opt_len,
                                    ciphertext, &ciphertext_len);
  if(err < 0) {
    LOG_ERR("oscore_protect_request failed: %d\n", err);
    return;
  }

  uint8_t n = oscore_opt[0] & 0x07;
  saved_piv_len = n;
  memcpy(saved_piv, oscore_opt + 1, n);
  saved_kid_len = (uint8_t)(oscore_opt_len - 1 - n);
  memcpy(saved_kid, oscore_opt + 1 + n, saved_kid_len);

  uint8_t pkt[1 + OSCORE_OPT_MAX_LEN + sizeof(inner) + OSCORE_TAG_LEN];
  size_t pos = 0;
  pkt[pos++] = (uint8_t)oscore_opt_len;
  memcpy(pkt + pos, oscore_opt, oscore_opt_len); pos += oscore_opt_len;
  memcpy(pkt + pos, ciphertext, ciphertext_len); pos += ciphertext_len;

  LOG_INFO("Sending OSCORE GET (%zu bytes UDP)\n", pos);
  simple_udp_sendto(&oscore_udp, pkt, pos, server_addr);
}
/*---------------------------------------------------------------------------*/
PROCESS(edhoc_oscore_c5t_client, "EDHOC+OSCORE c5t Client");
AUTOSTART_PROCESSES(&edhoc_oscore_c5t_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(edhoc_oscore_c5t_client, ev, data)
{
  static struct etimer timer;
  static struct etimer retx;
  static struct etimer settle;
  static struct etimer hs_deadline;
  static uint8_t get_attempt;
  static bench_stats_t stats;
  static uint32_t bench_samples[BENCH_ITERS];  /* successful durations (us) for median/p95 */
  static int iter;
  static rtimer_clock_t t0, t1, rep0;
  static bool hs_ok, was_down;
  static int8_t ret;

  PROCESS_BEGIN();

  bench_marker_init();                 /* no-op unless -DENERGY_MARKER_PIN */
  bench_print_fw_build(ECC_BACKEND_NAME);
  printf("[BENCH] label=%s iters=%d (timing = EDHOC handshake run->finished)\n",
         BENCH_LABEL, BENCH_ITERS);

  edhoc_profile_init();   /* enable the DWT cycle counter (no-op if profiling off) */

  simple_udp_register(&oscore_udp, OSCORE_UDP_PORT, NULL, OSCORE_UDP_PORT,
                       oscore_response_callback);

  etimer_set(&timer, CLOCK_SECOND * 5);
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
  }
  /* Joined the DODAG and the root is reachable -- always printed (not
   * log-gated) so the operator sees the node is ready before timing starts. */
  printf("[BENCH] connected: joined DODAG, hops=%d -- starting %s (%d iters)\n",
         bench_rpl_hops(), BENCH_LABEL, BENCH_ITERS);

  bench_stats_init(&stats);

  for(iter = 0; iter < BENCH_ITERS; iter++) {
    /* Recover before each iteration: RPL churn or a prior failure may have
     * dropped the route -- wait until the root is reachable again. Time any
     * DODAG repair we wait through, so a slow repair is recorded (rpl_rep_ms). */
    bench_stats_repair_reset_last(&stats);
    rep0 = bench_time_now();
    was_down = false;
    while(!NETSTACK_ROUTING.node_is_reachable()) {
      was_down = true;
      etimer_set(&timer, CLOCK_SECOND * 2);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    }
    if(was_down) {
      bench_stats_add_repair(&stats, bench_elapsed_us(rep0, bench_time_now()));
    }
    /* (Re)build the credential key list each iteration -- edhoc_create_key_list
     * re-initialises it, so this is a clean per-iteration setup. */
    if(edhoc_create_key_list() != EDHOC_SUCCESS) {
      LOG_ERR("edhoc_create_key_list failed\n");
      break;
    }
    static cose_key_t client_key, server_key;
    memcpy(&client_key, &auth_c509_client_template, sizeof(cose_key_t));
    c509_test_attach_cert(&client_key);
    memcpy(&server_key, &auth_c509_server_template, sizeof(cose_key_t));
    memset(server_key.ecc.priv, 0, sizeof(server_key.ecc.priv));
    c509_test_attach_cert(&server_key);
    if(edhoc_add_key(&client_key) != EDHOC_SUCCESS ||
       edhoc_add_key(&server_key) != EDHOC_SUCCESS) {
      LOG_ERR("Failed to add EDHOC keys\n");
      break;
    }

    /* --- timed EDHOC handshake: run() -> EVT_FINISHED --- */
    hs_ok = false;
    oscore_ready = false;
    t0 = bench_time_now();
    bench_marker_high();               /* PPK2 energy window = this handshake */
    edhoc_client_run();
    /* Hard per-iteration deadline: abort a stuck handshake so it can't hang the
     * whole run on the protocol's internal retry budget. */
    etimer_set(&hs_deadline, CLOCK_SECOND * BENCH_HS_DEADLINE_S);
    while(1) {
      PROCESS_WAIT_EVENT();
      ret = edhoc_client_callback(ev, data);
      if(ret > 0) { t1 = bench_time_now(); bench_marker_low(); hs_ok = true; break; }
      if(ret < 0) { bench_marker_low(); hs_ok = false; LOG_ERR("EDHOC failure: %d\n", ret); break; }
      if(etimer_expired(&hs_deadline)) {
        bench_marker_low();
        hs_ok = false; LOG_ERR("bench: handshake deadline (%d s)\n",
                               BENCH_HS_DEADLINE_S); break;
      }
    }

    /* Re-attempts (EDHOC restarts) this handshake took; read before close. */
    uint32_t hs_attempts = edhoc_client_get_attempt();

    if(hs_ok) {
      uint32_t dur_us = bench_elapsed_us(t0, t1);
      bench_samples[stats.n] = dur_us;   /* store before add (stats.n = index) */
      bench_stats_add_us(&stats, dur_us, hs_attempts);

      /* Complete the cycle: derive OSCORE + one protected GET (untimed) so the
       * responder finishes this session and is ready for the next iteration. */
      oscore_ctx_t edhoc_out;
      if(edhoc_exporter_oscore(&edhoc_out, edhoc_ctx) >= 0 &&
         oscore_derive_context(&client_oscore, &edhoc_out) >= 0) {
        oscore_ready = true;
        static coap_endpoint_t server_ep;
        coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
#ifdef EDHOC_CONF_SERVER_FROM_ROOT
        /* OSCORE GET target = RPL root (responder); resolve dynamically to match
         * the EDHOC handshake fix (platform/FICR-derived node addressing). */
        {
          uip_ipaddr_t bench_root_ipaddr;
          if(NETSTACK_ROUTING.get_root_ipaddr(&bench_root_ipaddr)) {
            uip_ipaddr_copy(&server_ep.ipaddr, &bench_root_ipaddr);
          }
        }
#endif /* EDHOC_CONF_SERVER_FROM_ROOT */
        etimer_set(&timer, CLOCK_SECOND / 2);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
        get_attempt = 0;
        oscore_done = false;
        send_oscore_request(&server_ep.ipaddr);
        etimer_set(&retx, OSCORE_GET_RETX_T0);
        while(!oscore_done) {
          PROCESS_WAIT_EVENT();
          if(oscore_done) { break; }
          if(etimer_expired(&retx)) {
            if(get_attempt < OSCORE_GET_MAX_RETX) {
              get_attempt++;
              send_oscore_request(&server_ep.ipaddr);
              etimer_set(&retx,
                         OSCORE_GET_RETX_T0 << (get_attempt < 3 ? get_attempt : 3));
            } else {
              break;
            }
          }
        }
      }
    } else {
      bench_stats_add_fail(&stats);
    }

    edhoc_client_close();

    /* One self-contained cumulative-stats line per completed cycle
     * (incl. radio hops to the RPL root + re-attempts + debug indicator). */
    bench_stats_print(BENCH_LABEL, &stats, bench_rpl_hops(), BENCH_DBG);

    /* Settle before the next iteration; longer after a failure so RPL/ETX can
     * heal before hammering the link again. */
    etimer_set(&settle,
               CLOCK_SECOND * (hs_ok ? BENCH_SETTLE_S : BENCH_FAIL_SETTLE_S));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&settle));
  }

  printf("=== BENCH %s DONE: %lu ok / %lu fail of %d ===\n",
         BENCH_LABEL, (unsigned long)stats.n, (unsigned long)stats.fail,
         BENCH_ITERS);
  /* Repeat the build stamp with the result so a pasted block is self-identifying. */
  bench_print_fw_build(ECC_BACKEND_NAME);
  /* Robust final summary (median + p95) -- copy this line as the result. */
  bench_stats_print_final(BENCH_LABEL, &stats, bench_samples,
                          bench_rpl_hops(), BENCH_DBG);
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
