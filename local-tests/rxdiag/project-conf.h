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
 * The sender doesn't reassemble the big flights, so trimming its pools does not
 * affect the experiment (the leaf keeps the hardened config). */
#if defined(CONTIKI_TARGET_ZOUL) || defined(CONTIKI_TARGET_CC2538DK)
/* CC2538 root/sender (Firefly HW, or cc2538dk = the cooja-ng CC2538 stand-in):
 * minimal pools that fit the cc2538 32KB SRAM. */
#define QUEUEBUF_CONF_NUM 6
#if MAC_CONF_WITH_TSCH
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 4
#define TSCH_CONF_MAX_INCOMING_PACKETS   4
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 8
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
