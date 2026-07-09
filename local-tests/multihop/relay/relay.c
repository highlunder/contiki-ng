/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * \file
 *   Minimal RPL + TSCH 6LoWPAN forwarder for the multi-hop C509 experiments.
 *   Not the RPL root: it associates to the TSCH network built outward from the
 *   coordinator, joins the DODAG as a router, and forwards on the network
 *   stack's own path -- no application traffic of its own. Placed between the
 *   server (root, node 1) and the client (node N) to add hops.
 */
#include "contiki.h"
#include "contiki-net.h"
#if MAC_CONF_WITH_TSCH
#include "net/mac/tsch/tsch.h"
#endif

#include "sys/log.h"
#define LOG_MODULE "Relay"
#define LOG_LEVEL  LOG_LEVEL_INFO

/* Multi-hop TSCH EB floor: the deepest relay otherwise nearly stops beaconing
 * (Orchestra eb_per_time_source + RPL EB-period backoff once its trickle
 * stabilises with no child to reset it), so the next node downstream can never
 * associate. Re-assert a small fixed EB period periodically, overriding whatever
 * tsch_rpl_callback_new_dio_interval last set, so every joined relay keeps
 * advertising and the chain can extend hop by hop. */
#ifndef RELAY_EB_PERIOD
#define RELAY_EB_PERIOD (4 * CLOCK_SECOND)
#endif

/*---------------------------------------------------------------------------*/
PROCESS(relay_process, "RPL/TSCH relay");
AUTOSTART_PROCESSES(&relay_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(relay_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  LOG_INFO("Relay up: RPL router + 6LoWPAN forwarder (not root)\n");

  /* Report reachability + keep EBs flowing so downstream nodes can associate. */
  etimer_set(&et, CLOCK_SECOND * 5);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
#if MAC_CONF_WITH_TSCH
    if(tsch_is_associated) {
      tsch_set_eb_period(RELAY_EB_PERIOD);   /* re-assert the EB floor */
    }
#endif
    LOG_INFO("Relay reachable=%d\n", NETSTACK_ROUTING.node_is_reachable());
    etimer_reset(&et);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
