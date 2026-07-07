/*
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * rxdiag project-conf: match the HARDENED cert-DTLS-over-TSCH transport that the
 * real failing client already uses (TSCH buffer over-provisioning + 6LoWPAN
 * reassembly window + RPL parent-eviction guard). By keeping these identical to
 * the bench, the ladder holds transport constant and isolates the receive-path
 * (sync vs raw-async) as the ONLY variable -- if the raw path still drops 848 B,
 * it is not a buffer/MAXAGE/RPL problem (those are already applied here).
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO

/* Per-rung overridable logging (default quiet). Rung 3 sets these to DBG on the
 * command line to see whether uIP received the datagram at all. */
#ifndef LOG_CONF_LEVEL_IPV6
#define LOG_CONF_LEVEL_IPV6     LOG_LEVEL_WARN
#endif
#ifndef LOG_CONF_LEVEL_6LOWPAN
#define LOG_CONF_LEVEL_6LOWPAN  LOG_LEVEL_WARN
#endif

/* RPL parent-eviction guard (match the benches). */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

/* The RECEIVER-side reassembly hardening is what the bisection must hold constant;
 * that node is the nRF-DK leaf. The Firefly (cc2538) only runs the ROOT/sender and
 * has a tiny SRAM (FRSRAM), so the fat nRF-sized pools overflow it -- trim there.
 * The sender does not REASSEMBLE the big flights (that pool can stay small), but it
 * MUST FRAGMENT them on output: 6LoWPAN output allocates one queuebuf per fragment
 * up front and DROPS the whole datagram if queuebuf_numfree() < frags ("not enough
 * free bufs"). The 700..1000 B sweep needs 9..12 queuebufs, so QUEUEBUF_CONF_NUM=6
 * silently dropped every large datagram on the cc2538 sender and nothing >96 B ever
 * reached the air (the mixed cc2538->nRF 848 B delivery failure). TSCH must also be
 * able to hold the outgoing fragment burst to one neighbor. Size the sender's OUTPUT
 * pools (queuebuf + per-neighbor TSCH queue) for the 12-fragment worst case; keep the
 * reassembly pool small since the root never reassembles. */
#if defined(CONTIKI_TARGET_ZOUL) || defined(CONTIKI_TARGET_CC2538DK)
/* CC2538 root/sender (Firefly HW, or cc2538dk = the cooja-ng CC2538 stand-in). */
#define QUEUEBUF_CONF_NUM 16                 /* >= worst-case frags (1000 B => 12) + headroom.
                                              * NB: raising this further (tested at 24) does
                                              * NOT make the mixed cc2538->nRF 848 B sweep pass:
                                              * TSCH unicast to the leaf drains slower than the
                                              * sweep queues fragments, so a backlog holds most
                                              * queuebufs and free plateaus at ~needed-1. That
                                              * residual is a throughput limit, not a pool size. */
#if MAC_CONF_WITH_TSCH
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16  /* hold the full outgoing fragment burst */
#define TSCH_CONF_MAX_INCOMING_PACKETS   4
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 8   /* sender does not reassemble */
#define SICSLOWPAN_CONF_MAXAGE 160
#endif /* MAC_CONF_WITH_TSCH */
#else
/* nRF-DK leaf (and nRF root): full bench-matched transport provisioning. */
#define QUEUEBUF_CONF_NUM 24
#if MAC_CONF_WITH_TSCH
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16
#define TSCH_CONF_MAX_INCOMING_PACKETS   8
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 24
/* Reassembly window: default MAXAGE 8 => 0.5s, too short for slot-paced multi-
 * frag delivery. 160 => ~10s. Matches the bench MAXAGE hardening. */
#define SICSLOWPAN_CONF_MAXAGE 160
#endif /* MAC_CONF_WITH_TSCH */
#endif /* CONTIKI_TARGET_ZOUL */

#endif /* PROJECT_CONF_H_ */
