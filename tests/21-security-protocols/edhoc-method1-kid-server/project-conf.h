#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 1 (Sig|StaticDH): responder uses Static DH authentication.
 * RFC 9528 §3.3: R authenticates with static DH key (MAC-based, no signature).
 * I authenticates with ECDSA-P256 signature. */
#define EDHOC_CONF_METHOD   EDHOC_METHOD1
#define EDHOC_CONF_ROLE     EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_KID

/* RFC 9529 C_R (responder CID) = -8. */
#define EDHOC_CONF_CID 0x27

/* Own authentication KID (matches auth_rfc9529_static_dh_server.kid = 0x32).
 * Used as a Static DH key in Method 1 (no ECDSA signature from responder). */
#define EDHOC_AUTH_KID 0x32

/* Cipher suites (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG. */
#define CSPRNG_CONF_ENABLED 1

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Buffers. */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 256
#define EDHOC_CONF_MAX_BUFFER      256

/* Server-side EDHOC session watchdog. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
