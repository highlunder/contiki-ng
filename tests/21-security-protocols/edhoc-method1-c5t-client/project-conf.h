#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 1 (Sig|StaticDH) with C509 c5t credentials.
 * Initiator authenticates with ECDSA-P256 signature over MAC_3.
 * Responder authenticates with a static DH key (MAC-based, no signature).
 * Credential identified by c5t (8-byte truncated SHA-256 of C509 cert). */
#define EDHOC_CONF_METHOD       EDHOC_METHOD1
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* CID for initiator (RFC 9529 C_I = -24). */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_client_template.kid = 0x02).
 * Used as a Sig key in Method 1 (signs MAC_3 with ECDSA-P256). */
#define EDHOC_AUTH_KID 0x02

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_CONF_SUPPORTED_SUITE_2 EDHOC_CIPHERSUITE_6

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* c5t carries 8-byte hash; cert (~164 B) stored locally for hash matching. */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   384

/* Avoid block-wise for C509 exchange. */
#define COAP_MAX_CHUNK_SIZE 300

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

#define EDHOC_CONF_TIMEOUT 100000

/* RPL tuning for nRF52840 emulation.
 * See edhoc-oscore-client/project-conf.h for the full rationale. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */
#define LPM_CONF_MAX_PM                1

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
