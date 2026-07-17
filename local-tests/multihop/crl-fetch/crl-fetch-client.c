/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   E10 relying party: block-wise CoAP GET of /crl from the RPL root, repeated
 *   CRL_TRIALS times, reporting per-trial delivery/latency and a summary.
 *
 *   A trial counts as delivered only if the reassembled object is byte-identical
 *   to the expected CRL (the same generated crl-payload.h the server serves), so
 *   "ok" means the relying party really could have used the object -- not merely
 *   that some bytes arrived.
 *
 *   Latency is measured from the first request to the last block, i.e. the whole
 *   block-wise transaction (the metric a relying party actually waits on).
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include <stdio.h>
#include <string.h>
#include "contiki.h"
#include "contiki-net.h"
#include "coap-engine.h"
#include "coap-blocking-api.h"
#include "net/routing/routing.h"

#include "crl-payload.h"

#include "sys/log.h"
#define LOG_MODULE "CrlCli"
#define LOG_LEVEL  LOG_LEVEL_INFO

#ifndef CRL_TRIALS
#define CRL_TRIALS 3
#endif
/* Settle time before the first fetch: the multi-hop DODAG + TSCH schedule must
 * be stable, else trial 1 measures the join, not the fetch. 150 s is the 3-hop
 * figure from the M1 tuning; applied at every hop count so the settle is a
 * control rather than a per-cell variable. */
#ifndef CRL_START_DELAY_S
#define CRL_START_DELAY_S 150
#endif
#define CRL_START_DELAY (CRL_START_DELAY_S * CLOCK_SECOND)
#ifndef CRL_TRIAL_GAP
#define CRL_TRIAL_GAP (10 * CLOCK_SECOND)
#endif

/* Placeholder; the address is replaced by the resolved RPL root at runtime. */
#define SERVER_EP "coap://[fe80::201:1:1:1]"

static uint8_t rx_buf[CRL_PAYLOAD_LEN];
static uint32_t rx_len;
static uint32_t rx_blocks;
static bool rx_overflow;

/*---------------------------------------------------------------------------*/
static void
crl_chunk_handler(coap_message_t *response)
{
  const uint8_t *chunk;
  int len;

  if(response == NULL) {
    return;                       /* timeout: trial fails on the length check */
  }
  len = coap_get_payload(response, &chunk);
  if(len <= 0) {
    return;
  }
  if(rx_len + len > sizeof(rx_buf)) {
    rx_overflow = true;           /* server/client payload mismatch */
    return;
  }
  memcpy(rx_buf + rx_len, chunk, len);
  rx_len += len;
  rx_blocks++;
}
/*---------------------------------------------------------------------------*/
PROCESS(crl_fetch_client, "E10 CRL fetch client");
AUTOSTART_PROCESSES(&crl_fetch_client);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(crl_fetch_client, ev, data)
{
  static struct etimer timer;
  static coap_endpoint_t server_ep;
  static coap_message_t request[1];
  static uip_ipaddr_t root_ipaddr;
  static int trial, ok_count;
  static clock_time_t t0;
  static uint32_t ms, ms_sum, ms_min, ms_max;
  static int ok;

  PROCESS_BEGIN();

  LOG_INFO("E10 CRL client: expect variant=%s R=%d len=%d block=%d trials=%d\n",
           CRL_PAYLOAD_VARIANT, CRL_PAYLOAD_R, CRL_PAYLOAD_LEN,
           COAP_MAX_CHUNK_SIZE, CRL_TRIALS);

  /* Wait for the DODAG. */
  etimer_set(&timer, CLOCK_SECOND * 5);
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    etimer_reset(&timer);
  }
  LOG_INFO("Network reachable; settling %d s before first fetch\n",
           (int)(CRL_START_DELAY / CLOCK_SECOND));
  etimer_set(&timer, CRL_START_DELAY);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));

  coap_endpoint_parse(SERVER_EP, strlen(SERVER_EP), &server_ep);
  if(NETSTACK_ROUTING.get_root_ipaddr(&root_ipaddr)) {
    uip_ipaddr_copy(&server_ep.ipaddr, &root_ipaddr);
  } else {
    LOG_ERR("no RPL root address\n");
  }

  ms_min = 0xffffffff;
  ms_max = 0;
  ms_sum = 0;
  ok_count = 0;

  for(trial = 1; trial <= CRL_TRIALS; trial++) {
    rx_len = 0;
    rx_blocks = 0;
    rx_overflow = false;

    t0 = clock_time();
    coap_init_message(request, COAP_TYPE_CON, COAP_GET, 0);
    coap_set_header_uri_path(request, "/crl");
    COAP_BLOCKING_REQUEST(&server_ep, request, crl_chunk_handler);
    ms = (uint32_t)((clock_time() - t0) * 1000 / CLOCK_SECOND);

    /* Delivered == complete AND byte-exact. */
    ok = (!rx_overflow && rx_len == CRL_PAYLOAD_LEN &&
          memcmp(rx_buf, crl_payload, CRL_PAYLOAD_LEN) == 0);

    printf("[E10 trial] variant=%s R=%d trial=%d ok=%d bytes=%lu/%d blocks=%lu ms=%lu\n",
           CRL_PAYLOAD_VARIANT, CRL_PAYLOAD_R, trial, ok ? 1 : 0,
           (unsigned long)rx_len, CRL_PAYLOAD_LEN, (unsigned long)rx_blocks,
           (unsigned long)ms);

    if(ok) {
      ok_count++;
      ms_sum += ms;
      if(ms < ms_min) {
        ms_min = ms;
      }
      if(ms > ms_max) {
        ms_max = ms;
      }
    }

    if(trial < CRL_TRIALS) {
      etimer_set(&timer, CRL_TRIAL_GAP);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    }
  }

  /* Mean over delivered trials only; a failed trial has no meaningful latency. */
  printf("[E10 SUMMARY] fw:%s variant=%s R=%d len=%d block=%d trials=%d ok=%d "
         "fail=%d mean_ms=%lu min_ms=%lu max_ms=%lu\n",
         FW_BUILD_ID, CRL_PAYLOAD_VARIANT, CRL_PAYLOAD_R, CRL_PAYLOAD_LEN,
         COAP_MAX_CHUNK_SIZE, CRL_TRIALS, ok_count, CRL_TRIALS - ok_count,
         (unsigned long)(ok_count ? ms_sum / ok_count : 0),
         (unsigned long)(ok_count ? ms_min : 0), (unsigned long)ms_max);
  printf("E10-END\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
