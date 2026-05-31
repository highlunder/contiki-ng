#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_RPL  LOG_LEVEL_INFO

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

/* ---- 6LoWPAN / queuebuf ---- */
#define QUEUEBUF_CONF_NUM 16

/* ---- RPL ----
 * Default RPL_CONF_PARENT_TIMEOUT = 3 × DIO_INTERVAL_MIN ≈ 12 s, but the
 * border-router Trickle timer grows to 16-32 s between DIOs.  Set the timeout
 * to 30 × DIO_INTERVAL_MIN ≈ 122 s so the parent survives across several DIO
 * intervals while the DTLS handshake is in progress. */
#define RPL_CONF_PARENT_TIMEOUT 30

/* MRHOF default MAX_LINK_METRIC = 512 (ETX 4).  In the cooja-ng simulation
 * the native slip-radio bursts SLIP traffic that causes channel collisions;
 * consecutive MAC-burst failures during the DTLS handshake spike ETX far
 * beyond 512.  The slip-radio is the ONLY possible parent in this 1-hop
 * test, so a link-quality threshold serves no purpose here.  Set both limits
 * to values that accommodate the worst observed ETX (~1200+) with margin. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   16512

/* Reduce CSMA MAC retries from the default 7 to 3.  Fewer per-failure
 * attempts mean a smaller ETX contribution each time a burst of SLIP-driven
 * TX collisions occurs, preventing catastrophic ETX accumulation. */
#define CSMA_CONF_MAX_TX_RETRIES 3

/* ---- Platform ----
 * NODE_ID_OFFSET 2 → nRF52840 link-layer f4ce:3600:0000:0002,
 * link-local fe80::f6ce:3600:0:2, global (via RPL) fd00::f6ce:3600:0:2. */
#define NODE_ID_OFFSET 2
#define LPM_CONF_ENABLE 0
#define NRF52840_CCA_TIMEOUT_ITERATIONS 1000UL

#endif /* PROJECT_CONF_H_ */
