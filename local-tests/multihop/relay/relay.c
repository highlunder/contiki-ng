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

#include "sys/log.h"
#define LOG_MODULE "Relay"
#define LOG_LEVEL  LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
PROCESS(relay_process, "RPL/TSCH relay");
AUTOSTART_PROCESSES(&relay_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(relay_process, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

  LOG_INFO("Relay up: RPL router + 6LoWPAN forwarder (not root)\n");

  /* Periodically report reachability so the operator can see the chain form. */
  etimer_set(&et, CLOCK_SECOND * 10);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    LOG_INFO("Relay reachable=%d\n", NETSTACK_ROUTING.node_is_reachable());
    etimer_reset(&et);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
