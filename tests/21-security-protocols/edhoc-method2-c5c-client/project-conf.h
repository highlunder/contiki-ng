#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 2 (StaticDH|Sig) with C509 c5c (cert inline), initiator role.
 * Initiator uses static DH key; full C509 cert sent inline in MSG_3. */
#define EDHOC_CONF_METHOD       EDHOC_METHOD2
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* CID for initiator. */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_client_template.kid = 0x02). */
#define EDHOC_AUTH_KID 0x02

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* c5c carries full cert (~164 B) inline in MSG_2/MSG_3. */
#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   512
#define EDHOC_CONF_MAX_PAYLOAD_LEN 320

#define COAP_MAX_CHUNK_SIZE 300

/* Prevent competing EDHOC session from starting during MSG_2 transit. */
#undef  EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 1

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
