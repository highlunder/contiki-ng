#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 1 (Sig|StaticDH): initiator signs, responder uses static DH.
 * RFC 9528 §3.3: I authenticates with ECDSA-P256 signature over MAC_2;
 * R authenticates with a static DH key (no signature from responder). */
#define EDHOC_CONF_METHOD   EDHOC_METHOD1
#define EDHOC_CONF_ROLE     EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_KID

/* RFC 9529 C_I (initiator CID) = -24. */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_rfc9529_static_dh_client.kid = 0x2b).
 * Used as a Signature key in Method 1 (initiator signs MAC_3). */
#define EDHOC_AUTH_KID 0x2b

/* Cipher suites supported. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_CONF_SUPPORTED_SUITE_2 EDHOC_CIPHERSUITE_6

/* Enable Cryptographically Secure PRNG for EDHOC ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* Buffers. */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 256
#define EDHOC_CONF_MAX_BUFFER      256

/* EDHOC session watchdog. */
#define EDHOC_CONF_TIMEOUT 100000

/* RPL tuning for nRF52840 emulation.
 * Relaxed MRHOF thresholds prevent the RPL DAG from being torn down during
 * transient MAC NACKs that occur under emulated radio conditions.
 * LPM_CONF_MAX_PM=1 keeps the radio responsive during DAG formation.
 * See edhoc-oscore-client/project-conf.h for the full rationale. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */
#define LPM_CONF_MAX_PM                1

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
