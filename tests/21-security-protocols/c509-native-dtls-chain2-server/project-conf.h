#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG

/* ---- DTLS / C509 ---- */
#define WITH_DTLS                  1
#define COAP_DTLS_CONF_WITH_CERT   1
#define COAP_DTLS_CONF_WITH_C509   1
#define COAP_DTLS_CONF_WITH_SERVER 1

/* ---- Heap ---- */
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)

/* ---- Mbed TLS ---- */
#define MBEDTLS_SSL_MAX_CONTENT_LEN     4096
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* ---- CoAP ---- */
#define COAP_MAX_CHUNK_SIZE 300

/* ---- CSPRNG ---- */
#define CSPRNG_CONF_ENABLED 1

/* ---- Routing ---- */
#define IS_NETWORK_ROUTING_ROOT 1

/* ---- 6LoWPAN ---- */
#define QUEUEBUF_CONF_NUM 16

/* ---- RPL link-metric tolerance (lossy-radio experiment) ----
 * Default RPL_MRHOF_CONF_MAX_LINK_METRIC is 512 (= ETX 4). Raised to match
 * the value already used by the EDHOC+OSCORE scenarios C/D, to test whether
 * the sr=0.5 RPL-collapse cliff is caused by this conservative default. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

#endif /* PROJECT_CONF_H_ */
