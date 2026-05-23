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
 * Mbed TLS requires ~256 KB for the TLS record buffers and certificate
 * parsing on nRF52840.  The nRF52840 DK has 256 KB RAM so this is tight;
 * leave the remaining RAM for stack and static data. */
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)

/* ---- Mbed TLS ----
 * 4 KB is enough for DTLS 1.2 records with a full certificate exchange.
 * The original 512-byte value was copied from a Zoul (32 KB RAM) config
 * and silently truncates the DTLS handshake on nRF52840. */
#define MBEDTLS_SSL_MAX_CONTENT_LEN     4096
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* ---- CSPRNG ---- */
#define CSPRNG_CONF_ENABLED 1

/* ---- Platform ---- */
/* NODE_ID_OFFSET 2 makes this node address f4ce:3600:0000:0002,
 * link-local fe80::f6ce:3600:0:2. */
#define NODE_ID_OFFSET 2
#define LPM_CONF_ENABLE 0

#endif /* PROJECT_CONF_H_ */
