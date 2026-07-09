#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 0, C509 c5t (cert-hash-by-reference), responder role. */
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* RFC 9529 C_R (responder CID). */
#define EDHOC_CONF_CID 0x27

/* Own authentication KID (matches auth_c509_server_template.kid = 0x01). */
#define EDHOC_AUTH_KID 0x01

/* Cipher suite (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* C509 cert buffers. */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   384

#define COAP_MAX_CHUNK_SIZE 300

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Server-side EDHOC session watchdog.  Matches the client timeout.  The server
 * (native process) waits for the nRF52840 client P256 ECDH + MSG_3 delivery.
 * 100 s is appropriate for both emulated and real hardware; reduce to ~30 s on
 * production deployments.  COAP_RESPONSE_TIMEOUT and RPL tuning are not needed
 * here — the server is native with no 802.15.4 radio or RPL stack. */
#define EDHOC_CONF_TIMEOUT 100000

/* ERR (not INFO): the responder's MSG_2 generation is ON THE CRITICAL PATH of the
 * latency the client benchmark measures (client times run()->FINISHED, which spans
 * the server's MSG_2). At INFO the server dumps several KB of EDHOC-Trace per
 * handshake (session summary, G_Y, TH_2/3/4, the 160 B CRED_R hex, plaintexts);
 * at 115200 baud that blocking serial time inflates the measured handshake by
 * hundreds of ms. ERR keeps the timing clean. Raise to INFO only for protocol
 * debugging, not for timing runs. */
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_ERR

#endif /* PROJECT_CONF_H_ */
