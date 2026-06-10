#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 1 (Sig|StaticDH) with C509 c5c credentials, initiator role.
 * Initiator authenticates with ECDSA-P256 signature over MAC_3; own full
 * C509 cert sent inline in MSG_3.  Responder's cert arrives inline in MSG_2;
 * Responder authenticates with a static DH key (MAC-based, no signature). */
#define EDHOC_CONF_METHOD       EDHOC_METHOD1
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5C

/* RFC 9529 C_I (initiator CID) = -24 in CBOR encoding. */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_client_template.kid = 0x02).
 * Used as a Sig key in Method 1 (signs MAC_3 with ECDSA-P256). */
#define EDHOC_AUTH_KID 0x02

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_CONF_SUPPORTED_SUITE_2 EDHOC_CIPHERSUITE_6

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* c5c carries full cert (~164 B) inline in MSG_2/MSG_3.
 * Extra buffer headroom for inline certs vs 8-byte c5t hash. */
#define EDHOC_CONF_MAX_CRED_LEN    256
#define EDHOC_CONF_MAX_BUFFER      512
#define EDHOC_CONF_MAX_PAYLOAD_LEN 320

/* MSG_3 includes the client's full cert.  Raise chunk size so the client
 * sends MSG_3 as a single packet; server must match (see server project-conf.h). */
#define COAP_MAX_CHUNK_SIZE 300

/* Prevent competing EDHOC session from starting during MSG_2 transit. */
#undef  EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 1

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
