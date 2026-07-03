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
/* Mutual auth: the DK sends its own client-certificate flight, ~11 6LoWPAN
 * fragments. Size the queue-buffer pool to hold a full large datagram burst so
 * fragments aren't dropped on transmit (matches the border-router's pool). */
#define QUEUEBUF_CONF_NUM 24

#ifdef LOCAL_TEST_DEBUG
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAC  LOG_LEVEL_INFO
#else
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_WARN
#endif

#endif /* PROJECT_CONF_H_ */
