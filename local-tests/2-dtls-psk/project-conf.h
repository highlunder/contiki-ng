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
#define QUEUEBUF_CONF_NUM 16

#ifdef LOCAL_TEST_DEBUG
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_MAC  LOG_LEVEL_INFO
#else
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_WARN
#endif

#endif /* PROJECT_CONF_H_ */
