#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node 2 in Cooja acts as network root (server). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#endif

/* EDHOC Method 2 (StaticDH|Sig) with C509 c5c, responder role.
 * Server signs MAC_2 with ECDSA-P256; sends cert inline in MSG_2. */
#define EDHOC_CONF_METHOD       EDHOC_METHOD2
#define EDHOC_CONF_ROLE         EDHOC_RESPONDER
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* CID for responder. */
#define EDHOC_CONF_CID 0x27

/* Own authentication KID (matches auth_c509_server_template.kid = 0x01). */
#define EDHOC_AUTH_KID 0x01

/* Cipher suite (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* c5c buffers. */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   512
#define EDHOC_CONF_MAX_PAYLOAD_LEN 320

#define COAP_MAX_CHUNK_SIZE 300

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Server-side EDHOC session watchdog.  COAP_RESPONSE_TIMEOUT and RPL tuning
 * are not needed here — the server is a native process. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
