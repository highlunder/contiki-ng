/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * rxdiag ROOT (sender / server role): TSCH coordinator + RPL root. Waits for a
 * trigger datagram from the leaf, then sweeps datagram sizes {700..1000} x TRIALS,
 * sending each raw UDP payload to BOTH the leaf's SYNC and RAW listener ports so a
 * single sweep compares the two receive paths head-to-head. Downstream direction
 * (root->leaf) mirrors the real server->client cert flight. See rxdiag.h.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/mac/tsch/tsch.h"
#include "net/ipv6/uip-debug.h"
#include "sys/node-id.h"
#include "rxdiag.h"
#include <stdio.h>
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "rxdiag-root"
#define LOG_LEVEL  LOG_LEVEL_WARN

static struct simple_udp_connection trig_conn;   /* recv triggers, send sweep */

static const uint16_t rxdiag_sizes[RXDIAG_NSIZES] = RXDIAG_SIZES_INIT;
static uint8_t txbuf[RXDIAG_MAXLEN];

/* Set by the trigger callback; consumed by the sweep process. */
static volatile uint8_t  sweep_req;
static uip_ipaddr_t      leaf_addr;

PROCESS(rxdiag_root_proc, "rxdiag-root");
AUTOSTART_PROCESSES(&rxdiag_root_proc);

/*---------------------------------------------------------------------------*/
static void
trig_rx(struct simple_udp_connection *c,
        const uip_ipaddr_t *sender_addr, uint16_t sender_port,
        const uip_ipaddr_t *receiver_addr, uint16_t receiver_port,
        const uint8_t *data, uint16_t datalen)
{
  uip_ipaddr_copy(&leaf_addr, sender_addr);
  sweep_req = 1;
  printf("[ROOT] trigger from ");
  uip_debug_ipaddr_print(sender_addr);
  printf(" (len=%u) -> starting sweep\n", (unsigned)datalen);
}
/*---------------------------------------------------------------------------*/
static void
send_one(uint16_t size, uint16_t port, unsigned trial)
{
  unsigned frags = (size + 89) / 90;
  memset(txbuf, (uint8_t)size, size);
  txbuf[0] = (uint8_t)(size >> 8);
  txbuf[1] = (uint8_t)(size & 0xff);
  printf("[ROOT] send size=%u frags~%u port=%u trial=%u\n",
         (unsigned)size, frags, (unsigned)port, trial);
  simple_udp_sendto_port(&trig_conn, txbuf, size, &leaf_addr, port);
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(rxdiag_root_proc, ev, data)
{
  static struct etimer et;
  static unsigned i, t;

  PROCESS_BEGIN();

  NETSTACK_ROUTING.root_start();
#if MAC_CONF_WITH_TSCH
  tsch_set_coordinator(1);
#endif
  NETSTACK_MAC.on();

  /* remote_port 0 -> we choose the destination port per send via _sendto_port. */
  simple_udp_register(&trig_conn, RXDIAG_TRIG_PORT, NULL, 0, trig_rx);

  printf("[ROOT] up as coordinator/root; waiting for leaf triggers on port %u\n",
         (unsigned)RXDIAG_TRIG_PORT);

  while(1) {
    /* Wait for a trigger. */
    etimer_set(&et, CLOCK_SECOND);
    while(!sweep_req) {
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
      etimer_reset(&et);
    }
    sweep_req = 0;

    printf("[ROOT] SWEEP BEGIN\n");
    for(i = 0; i < RXDIAG_NSIZES; i++) {
      for(t = 1; t <= RXDIAG_TRIALS; t++) {
        /* Same size to BOTH listeners so sync-vs-raw is directly comparable. */
        send_one(rxdiag_sizes[i], RXDIAG_SYNC_PORT, t);
        etimer_set(&et, (CLOCK_SECOND * RXDIAG_GAP_MS) / 1000);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

        send_one(rxdiag_sizes[i], RXDIAG_RAW_PORT, t);
        etimer_set(&et, (CLOCK_SECOND * RXDIAG_GAP_MS) / 1000);
        PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
      }
    }
    printf("[ROOT] SWEEP DONE\n");
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
