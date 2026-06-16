#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG

/* ---- DTLS / PSK ---- */
#define WITH_DTLS                  1
#define COAP_DTLS_CONF_WITH_PSK    1
#define COAP_DTLS_CONF_WITH_SERVER 1

/* ---- Heap ---- */
#define HEAPMEM_CONF_ARENA_SIZE (32 * 1024)

/* ---- Mbed TLS ---- */
#define MBEDTLS_SSL_MAX_CONTENT_LEN     4096
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED

/* ---- CoAP ---- */
#define COAP_MAX_CHUNK_SIZE 300

/* ---- CSPRNG ---- */
#define CSPRNG_CONF_ENABLED 1

/* ---- Routing ---- */
#define IS_NETWORK_ROUTING_ROOT 1

/* ---- 6LoWPAN ---- */
#define QUEUEBUF_CONF_NUM 16

#endif /* PROJECT_CONF_H_ */
