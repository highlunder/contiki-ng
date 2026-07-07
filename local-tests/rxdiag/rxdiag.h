/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * rxdiag -- on-hardware TSCH receive-path bisection ladder (shared config).
 *
 * The failure under investigation: cert-DTLS over TSCH fails on real nRF52840-DK
 * because an ~848 B (9-fragment) server flight is 6LoWPAN-reassembled and handed
 * to IP ("received IPv6 packet with len 848") but never picked up by the client's
 * coap-secure receive path -- while PSK-DTLS (small flight), CSMA (any size), and
 * bulk simple_udp (13-frag round-trips) all work, and the cooja-ng emulator picks
 * up 848 B (indeed up to 1000 B) flawlessly. So the bug is real-RF/TSCH-timing
 * specific and must be narrowed ON HARDWARE.
 *
 * Topology mirrors the real failure direction (server->client, downstream):
 *   ROOT = TSCH coordinator + RPL root = the SENDER (server role).
 *   LEAF = joining node under test = the RECEIVER (client role).
 * The leaf runs TWO listeners for the SAME datagram sizes so a single sweep
 * compares them head-to-head:
 *   - SYNC  port: simple_udp callback (the "works" control -- dedicated,
 *                 always-parked process).
 *   - RAW   port: a raw udp_new()+bind conn whose owning process waits on
 *                 tcpip_event exactly like coap-uip's coap_engine (the suspect).
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RXDIAG_H_
#define RXDIAG_H_

/* Leaf -> root trigger (small); root replies with the full sweep to the leaf. */
#define RXDIAG_TRIG_PORT   5690
/* Leaf listeners the root blasts the sweep at. */
#define RXDIAG_SYNC_PORT   5688   /* simple_udp synchronous callback           */
#define RXDIAG_RAW_PORT    5689   /* raw udp_conn + tcpip_event wait (coap-like)*/

/* Bracket the 756 B (emulator flight, works) -> 848 B (hardware fail) gap and go
 * well beyond, at ~1-fragment (90 B) resolution. Same set as coap-rx-probe. */
#define RXDIAG_SIZES_INIT { 700, 760, 820, 848, 880, 920, 1000 }
#define RXDIAG_NSIZES     7
#define RXDIAG_MAXLEN     1024    /* tx/scratch buffer; largest sweep size fits */

#ifndef RXDIAG_TRIALS
#define RXDIAG_TRIALS      4      /* datagrams per size, per listener           */
#endif
#ifndef RXDIAG_GAP_MS
#define RXDIAG_GAP_MS      1500   /* settle between sends (TSCH is slot-paced)   */
#endif

/* First 2 payload bytes carry the intended size (big-endian) so a truncated or
 * clobbered receive is self-evident from the logged length-vs-claimed size. */

#endif /* RXDIAG_H_ */
