/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Rung 1 of the Firefly-gateway OTA test ladder: pure connectivity / RPL join.
 *
 *   No crypto, no server. This board is a plain RPL node: it joins the Firefly's
 *   DAG over 2.4 GHz, obtains a global fd00:: address, and then prints a
 *   heartbeat with its address and reachability every few seconds. Confirm
 *   from the gateway host with `ping6 <the printed fd00:: address>`.
 *
 *   This isolates "does the radio link + RPL join + downward route work?" from
 *   anything security-related, so the higher rungs can assume connectivity.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include "contiki.h"
#include "contiki-net.h"
#include "net/routing/routing.h"
#include "net/ipv6/uip-ds6.h"
#include "local-test-banner.h"

#include "sys/log.h"
#define LOG_MODULE "1-net-join"
#define LOG_LEVEL  LOG_LEVEL_INFO

#define HEARTBEAT_S 5

/*---------------------------------------------------------------------------*/
static void
print_global_addr(void)
{
  for(int i = 0; i < UIP_DS6_ADDR_NB; i++) {
    if(uip_ds6_if.addr_list[i].isused &&
       !uip_is_addr_linklocal(&uip_ds6_if.addr_list[i].ipaddr)) {
      LOG_INFO("global address: ");
      LOG_INFO_6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      LOG_INFO_("\n");
    }
  }
}
/*---------------------------------------------------------------------------*/
PROCESS(net_join_test, "1-net-join (RPL join / connectivity)");
AUTOSTART_PROCESSES(&net_join_test);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(net_join_test, ev, data)
{
  static struct etimer et;
  static int reachable_announced;

  PROCESS_BEGIN();

  local_test_banner("1-net-join", NULL, 0);
  LOG_INFO("Waiting to join the Firefly DAG over the radio...\n");

  etimer_set(&et, CLOCK_SECOND * HEARTBEAT_S);
  reachable_announced = 0;
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);

    if(NETSTACK_ROUTING.node_is_reachable()) {
      if(!reachable_announced) {
        LOG_INFO("=== REACHABLE: joined the DAG, root is reachable ===\n");
        reachable_announced = 1;
      }
      LOG_INFO("heartbeat: reachable. ");
      LOG_INFO_("ping me from the gateway host.\n");
      print_global_addr();
    } else {
      LOG_INFO("heartbeat: not reachable yet (joining)...\n");
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
