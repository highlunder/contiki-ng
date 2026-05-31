#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_IPV6 LOG_LEVEL_WARN

/* ---- DTLS / C509 ---- */
#define WITH_DTLS                1
#define COAP_DTLS_CONF_WITH_CERT 1
#define COAP_DTLS_CONF_WITH_C509 1

/* ---- Heap ---- */
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)

/* ---- Mbed TLS ---- */
#define MBEDTLS_SSL_MAX_CONTENT_LEN     4096
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* ---- CSPRNG ---- */
#define CSPRNG_CONF_ENABLED 1

/* ---- 6LoWPAN / queuebuf ----
 * Extra buffers: as the final hop, the client both receives 6LoWPAN fragments
 * from I and sends its own DTLS fragments, so it needs more queue space. */
#define QUEUEBUF_CONF_NUM 24

/* ---- Timing ----
 * 3-hop RPL convergence: DIO propagates two extra hops vs the 1-hop test
 * (BR joins first, then I, then C).  Each hop doubles the Trickle interval,
 * so full convergence with DAO registration can take 90-120 s at real-time
 * simulation speed.  Add margin beyond that for the ETX probing cycle. */
#define CONNECT_DELAY_S     90
#define HANDSHAKE_TIMEOUT_S 120

/* ---- RPL ---- */
#define RPL_CONF_PARENT_TIMEOUT        30
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

/* ---- CSMA ---- */
#define CSMA_CONF_MAX_TX_RETRIES 3

/* ---- Platform ---- */
#define LPM_CONF_ENABLE 0
#define NRF52840_CCA_TIMEOUT_ITERATIONS 1000UL

#endif /* PROJECT_CONF_H_ */
