/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- DTLS / C509 (same as c509-native-dtls-client) ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG
#define WITH_DTLS                  1
#define COAP_DTLS_CONF_WITH_CERT   1
#define COAP_DTLS_CONF_WITH_C509   1
#define COAP_DTLS_CONF_WITH_CLIENT 1
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)
#define MBEDTLS_SSL_MAX_CONTENT_LEN     4096
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED
#define COAP_MAX_CHUNK_SIZE 300
#define CSPRNG_CONF_ENABLED 1
#define QUEUEBUF_CONF_NUM 16

/* ---- Phase-2 SLIP uplink: logs -> nRF USB CDC, SLIP -> UART0 (VCOM) ----
 * See PHASE2-SLIP-README.md. NRF52840_NATIVE_USB=1 is set in the Makefile. */
#define DBG_CONF_USB        1
#define SLIP_ARCH_CONF_USB  0

/* ---- setest server ----
 * The board uses CA-issued Type-2 C509 (custom in-handshake verify). setest's
 * self-signed Type-2 scenario is "B2" (5687); full interop with the board's
 * CA-issued Type-2 needs the setest out-of-band / patched-mbedTLS verify
 * (PLAN-c509-type2-dtls.md, Task 10). See PHASE2-SLIP-README.md. */
#ifndef PHASE2_SERVER_ADDR
#define PHASE2_SERVER_ADDR "fd00::1"
#endif
#ifndef PHASE2_SERVER_PORT
#define PHASE2_SERVER_PORT 5687
#endif

#endif /* PROJECT_CONF_H_ */
