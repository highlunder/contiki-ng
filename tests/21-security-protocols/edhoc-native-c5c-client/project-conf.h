#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 0, C509 c5c (cert inline delivery), initiator role. */
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* RFC 9529 C_I (initiator CID). */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_native_client_template.kid = 0x03). */
#define EDHOC_AUTH_KID 0x03

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* c5c carries full cert (~138 B) inline in MSG_2/MSG_3. */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   512
#define EDHOC_CONF_MAX_PAYLOAD_LEN 320

/* COAP_MAX_CHUNK_SIZE must match server (300) to avoid silent MSG_3 truncation
 * in coap.c: the default 64-byte limit drops any payload larger than 64 B. */
#define COAP_MAX_CHUNK_SIZE 300

/* Prevent competing EDHOC session from starting during MSG_2 transit. */
#undef  EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 1

/* RPL tuning for nRF52840 emulation — see edhoc-oscore-c5c-client/project-conf.h. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */

#define OSCORE_UDP_PORT 5686

/* Keep the radio responsive during ECDH on real HW; harmless in emulation. */
#define LPM_CONF_MAX_PM 1

/* Conservative handshake timeout for emulated and real HW alike. */
#define EDHOC_CONF_TIMEOUT 100000
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
