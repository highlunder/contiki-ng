#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 1 (Sig|StaticDH) with C509 c5t credentials, responder role.
 * Responder authenticates with a static DH key (MAC-based, no signature).
 * Initiator authenticates with ECDSA-P256 signature over MAC_3.
 * Credential identified by c5t (8-byte truncated SHA-256 of C509 cert). */
#define EDHOC_CONF_METHOD       EDHOC_METHOD1
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* RFC 9529 C_R (responder CID) = -8. */
#define EDHOC_CONF_CID 0x27

/* Own authentication KID (matches auth_c509_server_template.kid = 0x01).
 * Used as a StaticDH key in Method 1 (MAC-based, no ECDSA from responder). */
#define EDHOC_AUTH_KID 0x01

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG. */
#define CSPRNG_CONF_ENABLED 1

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* c5t carries 8-byte hash; cert stored locally for verification. */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   384

/* Client sends MSG_3 (~90 B) as a single CoAP packet (no BLOCK1 because
 * client has COAP_MAX_CHUNK_SIZE=300).  Without raising the server limit
 * here, coap.c truncates any payload > 64 to 64 bytes, breaking MSG_3. */
#define COAP_MAX_CHUNK_SIZE 300

/* Server-side EDHOC session watchdog. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
