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

/* Own authentication KID (matches auth_c509_server_template_bp256.kid = 0x24). */
#define EDHOC_AUTH_KID 0x24

/* Cipher suite (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Scenario D (PLAN-c509-lice-followup.md SS5.3.3): COSE_Sign1 credential key
 * uses brainpoolP256r1 instead of the cipher suite's nominal P-256. The
 * ephemeral ECDH (EDHOC_CURVE_P256, from EDHOC_CIPHERSUITE_2) is unaffected. */
#define uECC_SUPPORTS_brainpoolP256r1 1
#define EDHOC_CONF_SIGNATURE_CURVE EDHOC_CURVE_BRAINPOOLP256R1

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* C509 cert buffers (bp256 certs are 151 bytes). */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   384

#define COAP_MAX_CHUNK_SIZE 300

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Server-side EDHOC session watchdog.  Matches the client timeout.  100 s is
 * appropriate for both emulated and real hardware; reduce to ~30 s on
 * production deployments. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
