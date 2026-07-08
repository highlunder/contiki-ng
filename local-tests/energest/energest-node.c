/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * \file
 *   Minimal RPL node that reports its own radio duty cycle via the
 *   simple-energest service. Built twice per MAC:
 *     - ROOT=1  -> RPL root (+ TSCH coordinator), the network anchor
 *     - (default) leaf, whose LISTEN (idle-RX) duty cycle is the number of
 *       interest: ~100% under always-on CSMA vs a few % under duty-cycled TSCH.
 *   The emulator's energest PLUGIN models the CC2420 only, so this measures the
 *   nRF radio duty cycle firmware-side instead (the nrf ieee driver instruments
 *   ENERGEST_TYPE_LISTEN/TRANSMIT). Companion to TSCH-C509-VS-X509-LATENCY.md.
 */
#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#if MAC_CONF_WITH_TSCH
#include "net/mac/tsch/tsch.h"
#endif
#include "simple-energest.h"

#include "sys/log.h"
#define LOG_MODULE "Energest"
#define LOG_LEVEL  LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
PROCESS(energest_node, "Energest node");
AUTOSTART_PROCESSES(&energest_node);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(energest_node, ev, data)
{
  static struct etimer et;

  PROCESS_BEGIN();

#if MAC_CONF_WITH_TSCH
  if(IS_NETWORK_ROUTING_ROOT) {
    tsch_set_coordinator(1);
  }
#endif

  if(IS_NETWORK_ROUTING_ROOT) {
    NETSTACK_ROUTING.root_start();
    LOG_INFO("Role: ROOT / coordinator\n");
  } else {
    LOG_INFO("Role: LEAF (measuring idle-RX duty cycle)\n");
  }

  /* Periodic CPU/LPM/TX/RX(LISTEN) dwell + duty cycle over serial. */
  simple_energest_init();

  etimer_set(&et, CLOCK_SECOND * 10);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
