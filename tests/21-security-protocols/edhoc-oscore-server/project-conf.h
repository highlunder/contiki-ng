#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 0 (Sig|Sig) with KID credentials, responder role. */
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_KID

/* RFC 9529 C_R (responder CID) = -8 in CBOR encoding. */
#define EDHOC_CONF_CID 0x27

/* Own authentication KID (matches auth_rfc9529_static_dh_server.kid = 0x32). */
#define EDHOC_AUTH_KID 0x32

/* Cipher suites (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for EDHOC ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* OSCORE UDP port (separate from CoAP 5683 and DTLS 5684). */
#define OSCORE_UDP_PORT 5686

/* Enough buffer for OSCORE exchange. */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 256
#define EDHOC_CONF_MAX_BUFFER      256

/* Server-side EDHOC session watchdog.  The server (running as a native process
 * here) must wait for the nRF52840 client to complete P256 ECDH (~300 ms real
 * time) and transmit MSG_3.  100 s is appropriate for both emulated and real
 * hardware; reduce to ~30 s on production deployments with known client timing.
 *
 * Note: COAP_RESPONSE_TIMEOUT and RPL tuning are client-side concerns and are
 * not needed in the server project-conf because the server is a native process
 * (no 802.15.4 radio, no RPL, no CoAP retransmit path for EDHOC messages). */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
