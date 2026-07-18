/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * Pure-transport "bulk send" probe. Joins the RPL DODAG, then sends UDP
 * datagrams of INCREASING size to a host echo server and reports the round-trip
 * success rate per size. It deliberately uses plain UDP -- no DTLS, no CoAP
 * retransmit, no blockwise -- to isolate the 6LoWPAN-fragmentation / MAC
 * transport limit from the handshake logic, and find WHERE a multi-fragment
 * payload stops getting through (the open question for cert-DTLS over TSCH).
 *
 * Builds for CSMA or TSCH (MAKE_MAC=...); run the same probe on both to compare
 * where each MAC breaks. Host side: local-tests/tsch-bulk/udp-echo.py on the tun
 * (fd00::1), behind the same Firefly gateway the benches use. The host log shows
 * what it RECEIVED (uplink), the DK log shows round-trip ok (uplink+downlink),
 * so a divergence localises the failing direction.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uiplib.h"
#include <stdio.h>
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "bulk"
#define LOG_LEVEL  LOG_LEVEL_WARN

#ifndef BULK_SERVER
#define BULK_SERVER "fd00::1"
#endif
#ifndef BULK_PORT
#define BULK_PORT 7777
#endif
#ifndef BULK_TRIALS
#define BULK_TRIALS 8
#endif
#ifndef BULK_TIMEOUT_S
#define BULK_TIMEOUT_S 8          /* per-trial wait for the echo (TSCH is slow) */
#endif
#ifndef BULK_GAP_S
#define BULK_GAP_S 2              /* inter-trial settle so bursts don't pile up */
#endif

/* Payload sizes (bytes). ~90 B fits one 6LoWPAN fragment on 802.15.4, so the
 * approximate fragment count is ceil(size/90). The sweep spans 1..~13 fragments;
 * the DTLS certificate flight is ~11 fragments (~800-1000 B), so the 720-1040 B
 * rows bracket it. Override individual runs by rebuilding with a shorter list. */
static const uint16_t bulk_sizes[] = {
  40, 80, 160, 240, 320, 400, 560, 720, 880, 1040, 1152
};
#define BULK_NSIZES (sizeof(bulk_sizes) / sizeof(bulk_sizes[0]))

static struct simple_udp_connection udp_conn;
static uint8_t txbuf[1200];
static volatile uint16_t echo_len;
static volatile uint8_t got_echo;

PROCESS(tsch_bulk_proc, "tsch-bulk");
AUTOSTART_PROCESSES(&tsch_bulk_proc);

static void
udp_rx(struct simple_udp_connection *c, const uip_ipaddr_t *sa, uint16_t sp,
       const uip_ipaddr_t *ra, uint16_t rp, const uint8_t *d, uint16_t dlen)
{
  echo_len = dlen;
  got_echo = 1;
  process_poll(&tsch_bulk_proc);   /* wake the probe immediately on the echo */
}

PROCESS_THREAD(tsch_bulk_proc, ev, data)
{
  static struct etimer et;
  static uip_ipaddr_t dest;
  static unsigned i, t, ok;
  static uint16_t s;
  static unsigned frags;
  static clock_time_t t0;
  static unsigned long rtt_sum_ms;

  PROCESS_BEGIN();

  simple_udp_register(&udp_conn, BULK_PORT, NULL, BULK_PORT, udp_rx);

  etimer_set(&et, CLOCK_SECOND);
  while(!NETSTACK_ROUTING.node_is_reachable()) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
  }
  printf("[BULK] connected: joined DODAG -- echo [%s]:%u, %u sizes x %u trials "
         "(no DTLS, raw UDP)\n",
         BULK_SERVER, (unsigned)BULK_PORT, (unsigned)BULK_NSIZES,
         (unsigned)BULK_TRIALS);
  uiplib_ipaddrconv(BULK_SERVER, &dest);

  etimer_set(&et, CLOCK_SECOND * 5);   /* let the schedule settle after join */
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  for(i = 0; i < BULK_NSIZES; i++) {
    s = bulk_sizes[i];
    frags = (s + 89) / 90;
    ok = 0;
    rtt_sum_ms = 0;
    for(t = 0; t < BULK_TRIALS; t++) {
      memset(txbuf, (uint8_t)i, s);
      txbuf[0] = (uint8_t)(s >> 8);        /* stamp the size so the echo is unambiguous */
      txbuf[1] = (uint8_t)(s & 0xff);
      got_echo = 0;
      echo_len = 0;
      t0 = clock_time();
      simple_udp_sendto(&udp_conn, txbuf, s, &dest);
      etimer_set(&et, CLOCK_SECOND * BULK_TIMEOUT_S);
      PROCESS_WAIT_EVENT_UNTIL(got_echo || etimer_expired(&et));
      if(got_echo && echo_len == s) {
        ok++;
        rtt_sum_ms += (unsigned long)((clock_time() - t0) * 1000UL / CLOCK_SECOND);
      }
      etimer_set(&et, CLOCK_SECOND * BULK_GAP_S);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }
    printf("[BULK] size=%u frags~%u ok=%u/%u rtt_avg_ms=%lu\n",
           (unsigned)s, frags, ok, (unsigned)BULK_TRIALS,
           ok ? (rtt_sum_ms / ok) : 0UL);
  }
  printf("[BULK] DONE\n");
  PROCESS_END();
}
