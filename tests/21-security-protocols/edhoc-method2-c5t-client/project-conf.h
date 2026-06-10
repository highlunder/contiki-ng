#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 2 (StaticDH|Sig) with C509 c5t credentials.
 * Initiator authenticates with a static DH key (no signature from client).
 * Responder authenticates with ECDSA-P256 signature over MAC_2.
 * Credential is identified by c5t (truncated SHA-256 hash of C509 cert). */
#define EDHOC_CONF_METHOD       EDHOC_METHOD2
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* CID for initiator (RFC 9529 C_I = -24). */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_client_template.kid = 0x02).
 * The credential is identified by c5t hash of the cert, not bare KID. */
#define EDHOC_AUTH_KID 0x02

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* C509 cert is ~164 bytes; c5t carries 8-byte hash not full cert. */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   384

/* Avoid block-wise for C509 exchange. */
#define COAP_MAX_CHUNK_SIZE 300

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* --- Timing / RPL tuning — emulated vs real nRF52840 hardware ---
 * See edhoc-oscore-client/project-conf.h for the full rationale. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */
#define LPM_CONF_MAX_PM 1
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
