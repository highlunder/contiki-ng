/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * Rung 4: DTLS + C509 Type-2 (same crypto config as c509-native-dtls-client),
 * radio uplink.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define WITH_DTLS                  1
#define COAP_DTLS_CONF_WITH_CERT   1
#define COAP_DTLS_CONF_WITH_C509   1
#define COAP_DTLS_CONF_WITH_CLIENT 1
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)
#define MBEDTLS_SSL_MAX_CONTENT_LEN 4096
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define COAP_MAX_CHUNK_SIZE 300
#define CSPRNG_CONF_ENABLED 1
/* Bound the post-handshake CoAP GET: a lost response gives up in ~20 s (2
 * retransmits at 4 s + 8 s) instead of the ~100 s default budget. The GET is an
 * untimed liveness check (its loss -> get_fail, not a handshake fail), so a tight
 * bound just stops it stalling the run on a lossy/slotted (TSCH) link.
 * (undef first: the coap-constants.h default is pulled in ahead of project-conf
 * on the DTLS path, so a plain #define would -Werror as a redefinition.) */
#undef  COAP_RESPONSE_TIMEOUT
#define COAP_RESPONSE_TIMEOUT 4
#undef  COAP_MAX_RETRANSMIT
#define COAP_MAX_RETRANSMIT   2
/* Mutual auth: the DK sends its own client-certificate flight, ~11 6LoWPAN
 * fragments. Size the queue-buffer pool to hold a full large datagram burst so
 * fragments aren't dropped on transmit (matches the border-router's pool). */
#define QUEUEBUF_CONF_NUM 24

/* RPL parent-eviction guard (matches the EDHOC benches). 100 rapid back-to-back
 * DTLS handshakes send bursty ~11-fragment cert flights; the NOACKs from those
 * bursts drive the single parent's ETX past the DEFAULT MRHOF cap (512 = ETX 4)
 * and evict it -> "no parent, scheduling periodic DIS" -> a multi-second DODAG
 * repair, and a failed handshake during the outage. Raising the ceiling to
 * ETX 128 lets ETX spike transiently without losing the (only) parent. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

/* --- TSCH buffer over-provisioning for the certificate flight (TSCH builds only;
 * CSMA byte-for-byte unchanged). dtls-c509 reconstructs to the SAME 364 B X.509
 * DER as x509, so it sends the identical ~11-fragment cert record and needs the
 * identical bump. Keep in sync with dtls-x509-bench/project-conf.h and
 * examples/rpl-border-router/project-conf.h. NOT applied to EDHOC/PSK-DTLS
 * (message-oriented / no cert). See paper_space/LICE-followup/NOTES-robustness-under-loss.md
 * (successor of the former PLAN-cd-robustness-tradeoff.md) + autoPKI.tex. */
#if MAC_CONF_WITH_TSCH
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16
#define TSCH_CONF_MAX_INCOMING_PACKETS   8
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 24
/* Root-cause fix: 6LoWPAN reassembly window 0.5 s (default) -> 10 s, so a
 * slot-paced multi-fragment cert flight isn't discarded mid-reassembly on TSCH.
 * See dtls-x509-bench/project-conf.h. Keep in sync with the border-router. */
#define SICSLOWPAN_CONF_MAXAGE 160
#endif /* MAC_CONF_WITH_TSCH */

#ifdef LOCAL_TEST_DEBUG
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAC  LOG_LEVEL_INFO
#else
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_WARN
#endif

#endif /* PROJECT_CONF_H_ */
