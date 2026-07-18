/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * Rung 2: DTLS + PSK (same crypto config as psk-native-dtls-client), radio uplink.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define WITH_DTLS                   1
#define COAP_DTLS_CONF_WITH_PSK     1
#define COAP_DTLS_CONF_WITH_CLIENT  1
#define HEAPMEM_CONF_ARENA_SIZE (32 * 1024)
#define MBEDTLS_SSL_MAX_CONTENT_LEN 4096
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
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
#define QUEUEBUF_CONF_NUM 16

/* RPL parent-eviction guard (matches the EDHOC benches). 100 rapid back-to-back
 * DTLS handshakes send bursty flights; the NOACKs from those bursts drive the
 * single parent's ETX past the DEFAULT MRHOF cap (512 = ETX 4) and evict it ->
 * "no parent, scheduling periodic DIS" -> a multi-second DODAG repair, and a
 * failed handshake during the outage. Raising the ceiling to ETX 128 lets ETX
 * spike transiently without losing the (only) parent. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

#ifdef LOCAL_TEST_DEBUG
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAC  LOG_LEVEL_INFO
#else
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_WARN
#endif

#endif /* PROJECT_CONF_H_ */
