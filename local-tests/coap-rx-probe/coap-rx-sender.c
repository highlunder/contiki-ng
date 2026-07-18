/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * coap-secure RECEIVE-PATH probe (sender side).
 *
 * The open question: cert-DTLS over TSCH fails on hardware because the client's
 * coap/DTLS receive path does not pick up a large (~848 B) REASSEMBLED datagram,
 * while plain simple_udp carries the same 13-fragment datagrams fine (tsch-bulk).
 * The Contiki DTLS *server* can only emit ~756 B flights (single leaf cert;
 * mbedTLS drops the self-signed root so a chain can't inflate it), so the
 * emulator handshake never exercises >756 B and always passes -- 90 B short of
 * setest's 848 B, a gap that crosses NO buffer limit (uip_buf 1280, mbedTLS
 * content-len 1224).
 *
 * This probe removes the cert-size constraint: it sends RAW UDP datagrams of
 * increasing size straight at the receiver's coap-secure port (5684), so they
 * land on the exact coap-uip dispatch path (coap_engine PROCESS -> tcpip_event
 * -> uip_newdata -> lport==SECURE_PORT -> process_secure_data). Build the
 * receiver (x509-native-dtls-server) with -DCOAP_UIP_RX_DEBUG and watch its
 * "[COAP-UIP] newdata ... len=" lines: the size at which those STOP appearing
 * (while 6LoWPAN still reassembles) is exactly where the coap async receive path
 * drops the datagram. No DTLS parse succeeds (garbage bytes) and no reply comes
 * back -- we only care whether the receiver's coap engine SEES each size.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include <stdio.h>
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "crxp"
#define LOG_LEVEL  LOG_LEVEL_WARN

/* coap-secure server port on the receiver (SERVER_LISTEN_SECURE_PORT). */
#ifndef CRXP_PORT
#define CRXP_PORT 5684
#endif
#ifndef CRXP_TRIALS
#define CRXP_TRIALS 4
#endif
#ifndef CRXP_GAP_S
#define CRXP_GAP_S 3              /* settle between sends (TSCH is slow) */
#endif

/* Bracket the 756 B (emulator flight, works) -> 848 B (hardware setest, fails)
 * gap and go beyond, at ~1-fragment (90 B) resolution. */
static const uint16_t crxp_sizes[] = {
  700, 760, 820, 848, 880, 920, 1000
};
#define CRXP_NSIZES (sizeof(crxp_sizes) / sizeof(crxp_sizes[0]))

static struct simple_udp_connection udp_conn;
static uint8_t txbuf[1100];

PROCESS(coap_rx_sender_proc, "coap-rx-sender");
AUTOSTART_PROCESSES(&coap_rx_sender_proc);

PROCESS_THREAD(coap_rx_sender_proc, ev, data)
{
  static struct etimer et;
  static uip_ipaddr_t dest;
  static unsigned i, t;
  static uint16_t s;
  static unsigned frags;

  PROCESS_BEGIN();

  /* Register a local conn just so we can send; we never expect a reply. */
  simple_udp_register(&udp_conn, CRXP_PORT + 1, NULL, CRXP_PORT, NULL);

  etimer_set(&et, CLOCK_SECOND);
  while(!NETSTACK_ROUTING.node_is_reachable() ||
        !NETSTACK_ROUTING.get_root_ipaddr(&dest)) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
  }
  printf("[CRXP] connected: reachable, root resolved; sweeping %u sizes x %u "
         "trials to root port %u (raw UDP, no DTLS)\n",
         (unsigned)CRXP_NSIZES, (unsigned)CRXP_TRIALS, (unsigned)CRXP_PORT);

  etimer_set(&et, CLOCK_SECOND * 5);   /* let the TSCH schedule settle */
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  for(i = 0; i < CRXP_NSIZES; i++) {
    s = crxp_sizes[i];
    frags = (s + 89) / 90;
    for(t = 0; t < CRXP_TRIALS; t++) {
      memset(txbuf, (uint8_t)i, s);
      txbuf[0] = (uint8_t)(s >> 8);
      txbuf[1] = (uint8_t)(s & 0xff);
      printf("[CRXP] send size=%u frags~%u trial=%u\n",
             (unsigned)s, frags, (unsigned)(t + 1));
      simple_udp_sendto(&udp_conn, txbuf, s, &dest);
      etimer_set(&et, CLOCK_SECOND * CRXP_GAP_S);
      PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    }
  }
  printf("[CRXP] DONE\n");
  PROCESS_END();
}
