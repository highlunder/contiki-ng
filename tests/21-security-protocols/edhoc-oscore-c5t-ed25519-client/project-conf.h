#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 0, C509 c5t (cert-hash-by-reference), initiator role. */
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* RFC 9529 C_I (initiator CID). */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_client_template_ed25519.kid = 0x23). */
#define EDHOC_AUTH_KID 0x23

/* Cipher suite (must match server). */
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

/* Large enough CoAP chunk to avoid block-wise for C509 exchange. */
#define COAP_MAX_CHUNK_SIZE 300

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* --- Timing / RPL tuning — emulated vs real nRF52840 hardware ---
 * See edhoc-oscore-client/project-conf.h for the full rationale.
 *
 * COAP_RESPONSE_TIMEOUT (set in Makefile to 15 s, default 3 s):
 *   Keep 15 s for both environments — SEQUENCE_ERROR retry plus fragmentation.
 *
 * EDHOC_CONF_TIMEOUT (100 s): conservative for both emulated and real HW;
 *   reducible to ~30 s on production hardware.
 *
 * LPM_CONF_MAX_PM 1: required on real HW to keep the radio responsive during
 *   ECDH; also set in emulator for consistent behaviour.
 *
 * RPL_MRHOF_CONF_MAX_LINK_METRIC 16384 (= ETX 128, default 512 = ETX 4):
 *   Emulator: transient 8-NOACK burst on first MSG_1 raises ETX to ~832,
 *   which would evict the RPL parent and cause MSG_3 to be silently dropped.
 *   Real HW: not needed on a clean link, but safe to keep.
 *
 * RPL_MRHOF_CONF_MAX_PATH_COST 32768: paired with MAX_LINK_METRIC above.
 *
 * RPL_CONF_PARENT_TIMEOUT 30: no-op — unused by RPL Lite OS sources. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */

/* nRF52840: prevent deep power management so the radio stays responsive.
 * Required on real HW; also set in emulator for consistent behaviour. */
#define LPM_CONF_MAX_PM 1

/* EDHOC session watchdog: 100 s conservative for both emulated and real HW.
 * Reduce to ~30 s if tighter failure detection is needed on production HW. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

/* MbedTLS (pulled in for ed25519_verify's mbedtls_sha512) uses heapmem for
 * dynamic allocation; heapmem_alloc/calloc/free are only defined as macros
 * when HEAPMEM_CONF_ARENA_SIZE is set (os/lib/heapmem.h). 64 KiB matches the
 * c509-native-dtls-* precedents. */
#define HEAPMEM_CONF_ARENA_SIZE (64 * 1024)

#endif /* PROJECT_CONF_H_ */
