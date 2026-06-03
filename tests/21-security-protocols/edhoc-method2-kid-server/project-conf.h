#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 2 (StaticDH|Sig): responder uses Signature authentication.
 * RFC 9528 §3.3: R authenticates with a signature key (ECDSA-P256 / ES256).
 * I authenticates with a static DH key (no ECDSA signature from initiator). */
#define EDHOC_CONF_METHOD   EDHOC_METHOD2
#define EDHOC_CONF_ROLE     EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_KID

/* RFC 9529 C_R (responder CID) = -8 in CBOR encoding. */
#define EDHOC_CONF_CID 0x27

/* Own authentication KID (matches auth_rfc9529_static_dh_server.kid = 0x32).
 * Used as a Signature key in Method 2 (server signs MAC_2 for client to verify). */
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

/* Server-side EDHOC session watchdog.
 * Note: COAP_RESPONSE_TIMEOUT and RPL tuning are client-side concerns and are
 * not needed here because the server is a native process (no 802.15.4 radio,
 * no RPL, no CoAP retransmit path for EDHOC messages). */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
