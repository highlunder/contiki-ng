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

/* Own authentication KID (matches auth_c509_server_template_ed25519.kid = 0x24). */
#define EDHOC_AUTH_KID 0x24

/* Cipher suite (must match client). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Scenario D (PLAN-c509-lice-followup.md SS5.3.3): COSE_Sign1 credential key
 * uses Ed25519 (EdDSA, COSE alg=-8) instead of the cipher suite's nominal
 * ES256/P-256. The ephemeral ECDH (EDHOC_CURVE_P256, from EDHOC_CIPHERSUITE_2)
 * is unaffected. */
#define EDHOC_CONF_SIGNATURE_ALG EDDSA

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* C509 cert buffers (Ed25519 certs are 139/153 bytes). */
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

/* MbedTLS (pulled in for ed25519_verify's mbedtls_sha512) uses heapmem for
 * dynamic allocation; heapmem_alloc/calloc/free are only defined as macros
 * when HEAPMEM_CONF_ARENA_SIZE is set (os/lib/heapmem.h). 64 KiB matches the
 * c509-native-dtls-* precedents. */
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)

#endif /* PROJECT_CONF_H_ */
