#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG

/* ---- DTLS / C509 ---- */
#define WITH_DTLS                1
#define COAP_DTLS_CONF_WITH_CERT 1
#define COAP_DTLS_CONF_WITH_C509 1

/* ---- Heap ----
 * 64 KB required by Mbed TLS on nRF52840 (Cortex-M4 stack depth).
 * Cooja (x86) is generous with virtual memory, so this is safe there too. */
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)

/* ---- Mbed TLS ----
 * 4 KB needed for a full DTLS 1.2 handshake with certificate exchange;
 * see c509-hw-test/project-conf.h for why the smaller default truncates. */
#define MBEDTLS_SSL_MAX_CONTENT_LEN     4096
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* ---- CSPRNG ---- */
#define CSPRNG_CONF_ENABLED 1

/* ---- 6LoWPAN / queuebuf ---- */
#define QUEUEBUF_CONF_NUM 16

/* ---- Platform ---- */
/* NODE_ID_OFFSET 2 → nRF52840 link-layer f4ce:3600:0000:0002,
 * link-local fe80::f6ce:3600:0:2 (client address, distinct from server). */
#define NODE_ID_OFFSET 2
#define LPM_CONF_ENABLE 0
/* CCA busy-wait guard: see c509-hw-test/project-conf.h for rationale. */
#define NRF52840_CCA_TIMEOUT_ITERATIONS 1000UL

#endif /* PROJECT_CONF_H_ */
