#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_DBG
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG

/* ---- DTLS / C509 ---- */
#define WITH_DTLS               1
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

/* ---- 6LoWPAN / queuebuf ----
 * DTLS server flight (ServerHello+Cert+SKE+SHD) ≈ 765 bytes UDP, which
 * requires ~10 6LoWPAN fragments.  The 6LoWPAN output code needs
 * (fragment_count + 1) free queuebufs; the default pool of 8 is too small
 * and the packet is silently dropped.  nRF52840 has 256 KB RAM so 16 is fine. */
#define QUEUEBUF_CONF_NUM 16

/* ---- Platform ---- */
/* NODE_ID_OFFSET 1 makes this node address f4ce:3600:0000:0001,
 * link-local fe80::f6ce:3600:0:1, which the client hardcodes. */
#define NODE_ID_OFFSET 1
#define LPM_CONF_ENABLE 0
/* CCA busy-wait guard: Renode never fires CCABUSY/CCAIDLE so the default
 * 1,000,000-iteration loop generates 2M unhandled-register-read warnings
 * per transmission, crippling simulation throughput.  1000 is enough to
 * exit quickly in simulation; real hardware always delivers a result in
 * <128 µs so the guard never fires there. */
#define NRF52840_CCA_TIMEOUT_ITERATIONS 1000UL

#endif /* PROJECT_CONF_H_ */
