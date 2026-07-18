/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * Rung 3: DTLS + X.509 (same crypto config as x509-native-dtls-client), radio uplink.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define WITH_DTLS                  1
#define COAP_DTLS_CONF_WITH_CERT   1
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

/* --- TSCH defensive buffer/reassembly provisioning (TSCH builds only; CSMA is
 * byte-for-byte unchanged) ----------------------------------------------------
 * NOTE (2026-07-03): cooja-ng proved a Contiki<->Contiki X.509 DTLS handshake
 * completes over TSCH with the STOCK config (see emul/emul-dtls-x509-tsch.json),
 * so none of these are strictly required -- the hardware stall was a setest
 * (python-mbedtls) server-flight interop issue, not a client-firmware limit.
 * They are kept as low-cost hardening for the slow slotted link and matched on
 * the border-router:
 *  - queue / inbound / fragment-buffer pools sized to hold a full multi-fragment
 *    cert flight (the bulk probe needs 24 buffers for a 13-fragment datagram);
 *  - SICSLOWPAN_CONF_MAXAGE 160 => a 10 s 6LoWPAN reassembly window (default is
 *    MAXAGE 8 = 0.5 s), so a datagram whose fragments dribble in over the
 *    slot-paced link is not discarded mid-reassembly. Keep in sync with the
 *    border-router + dtls-c509. (The earlier COAP_MBEDTLS_MTU/MFL overrides were
 *    removed -- unnecessary, and they made the client's records unrepresentative.) */
#if MAC_CONF_WITH_TSCH
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16
#define TSCH_CONF_MAX_INCOMING_PACKETS   8
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 24
#define SICSLOWPAN_CONF_MAXAGE           160
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
