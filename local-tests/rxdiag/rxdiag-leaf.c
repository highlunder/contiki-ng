/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * rxdiag LEAF (receiver / client role): joins the root's DODAG, then periodically
 * triggers the root to blast the size sweep back down to it. Runs TWO listeners
 * for the SAME datagrams so one sweep compares the receive paths:
 *
 *   [SU]  simple_udp callback on RXDIAG_SYNC_PORT -- the "works" control (a
 *         dedicated process almost always parked at PROCESS_WAIT_EVENT()).
 *   [RAW] a raw udp_new()+udp_bind() conn on RXDIAG_RAW_PORT owned by a process
 *         whose loop is byte-for-byte the coap-uip dispatch: wait tcpip_event ->
 *         if(uip_newdata()) consume uip_datalen(). This is the suspect path.
 *
 * Each log line prints the RECEIVED length and the size the sender CLAIMED (first
 * two payload bytes), so a drop (size missing) or a truncation/clobber (len !=
 * claimed) is self-evident. Enable IPv6/6LoWPAN DBG (see project-conf per rung) to
 * see whether uIP even got "received IPv6 packet with len N" for a size that the
 * app never logs -- that localizes reassembly vs demux vs process-delivery.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-udp-packet.h"
#include "rxdiag.h"
#include <stdio.h>
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "rxdiag-leaf"
#define LOG_LEVEL  LOG_LEVEL_WARN

#ifndef RXDIAG_LEAF_SYNC
#define RXDIAG_LEAF_SYNC 1
#endif
#ifndef RXDIAG_LEAF_RAW
#define RXDIAG_LEAF_RAW  1
#endif

static uint8_t trigbuf[8];

static inline uint16_t
claimed_size(const uint8_t *p, uint16_t len)
{
  return (len >= 2) ? (uint16_t)((p[0] << 8) | p[1]) : 0;
}

/*---------------------------------------------------------------------------*/
#if RXDIAG_LEAF_SYNC
static struct simple_udp_connection sync_conn;
static void
sync_rx(struct simple_udp_connection *c,
        const uip_ipaddr_t *sender_addr, uint16_t sender_port,
        const uip_ipaddr_t *receiver_addr, uint16_t receiver_port,
        const uint8_t *data, uint16_t datalen)
{
  printf("[SU]  recv len=%u claimed=%u\n",
         (unsigned)datalen, (unsigned)claimed_size(data, datalen));
}
#endif /* RXDIAG_LEAF_SYNC */

/*---------------------------------------------------------------------------*/
#if RXDIAG_LEAF_RAW
/* Raw listener: replicate coap-uip's coap_engine dispatch exactly. */
PROCESS(rxdiag_raw_proc, "rxdiag-raw");
PROCESS_THREAD(rxdiag_raw_proc, ev, data)
{
  static struct uip_udp_conn *conn;
  PROCESS_BEGIN();

  conn = udp_new(NULL, 0, NULL);       /* owned by THIS process */
  if(conn != NULL) {
    udp_bind(conn, UIP_HTONS(RXDIAG_RAW_PORT));
  }
  printf("[RAW] listener bound port=%u conn=%p\n",
         (unsigned)RXDIAG_RAW_PORT, (void *)conn);

  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(ev == tcpip_event);
    if(uip_newdata()) {
      const uint8_t *p = (const uint8_t *)uip_appdata;
      printf("[RAW] recv len=%u claimed=%u lport=%u\n",
             (unsigned)uip_datalen(),
             (unsigned)claimed_size(p, (uint16_t)uip_datalen()),
             (unsigned)uip_ntohs(uip_udp_conn->lport));
    }
  }
  PROCESS_END();
}
#endif /* RXDIAG_LEAF_RAW */

/*---------------------------------------------------------------------------*/
PROCESS(rxdiag_leaf_proc, "rxdiag-leaf");
#if RXDIAG_LEAF_RAW
AUTOSTART_PROCESSES(&rxdiag_leaf_proc, &rxdiag_raw_proc);
#else
AUTOSTART_PROCESSES(&rxdiag_leaf_proc);
#endif

PROCESS_THREAD(rxdiag_leaf_proc, ev, data)
{
  static struct etimer et;
  static struct simple_udp_connection trig_conn;
  static uip_ipaddr_t root;
  static unsigned round;

  PROCESS_BEGIN();

#if RXDIAG_LEAF_SYNC
  simple_udp_register(&sync_conn, RXDIAG_SYNC_PORT, NULL, 0, sync_rx);
#endif
  /* Trigger channel: send to root's RXDIAG_TRIG_PORT. */
  simple_udp_register(&trig_conn, RXDIAG_TRIG_PORT + 1, NULL,
                      RXDIAG_TRIG_PORT, NULL);

  /* Join the DODAG. */
  etimer_set(&et, CLOCK_SECOND);
  while(!NETSTACK_ROUTING.node_is_reachable() ||
        !NETSTACK_ROUTING.get_root_ipaddr(&root)) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
  }
  printf("[LEAF] reachable, root resolved; SYNC=%d RAW=%d\n",
         (int)RXDIAG_LEAF_SYNC, (int)RXDIAG_LEAF_RAW);

  /* Let the schedule settle, then trigger the root's sweep repeatedly (each
   * trigger drives one full sweep; several rounds give repeatability). */
  etimer_set(&et, CLOCK_SECOND * 5);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  for(round = 1; round <= 3; round++) {
    trigbuf[0] = (uint8_t)round;
    printf("[LEAF] trigger round %u -> root\n", round);
    simple_udp_sendto(&trig_conn, trigbuf, sizeof(trigbuf), &root);
    /* Wait long enough for a full sweep (NSIZES*TRIALS*2 sends * gap) + slack. */
    etimer_set(&et, (CLOCK_SECOND *
                     ((RXDIAG_NSIZES * RXDIAG_TRIALS * 2 * RXDIAG_GAP_MS) / 1000
                      + 20)));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
  }
  printf("[LEAF] DONE\n");

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
