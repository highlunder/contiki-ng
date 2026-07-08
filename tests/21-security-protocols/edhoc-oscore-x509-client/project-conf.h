#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* cooja-ng-ge derives node IPv6 from the emulated FICR (not the node id), so the
 * hard-coded EDHOC_CONF_SERVER_EP host never matches. Resolve the responder =
 * RPL DAG root dynamically instead (harmless on real RF: root == responder). */
#define EDHOC_CONF_SERVER_FROM_ROOT 1

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 0, X.509 x5chain (cert inline delivery), initiator role. */
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_X509_X5C

/* RFC 9529 C_I (initiator CID). */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_x509_client_template.kid = 0x02). */
#define EDHOC_AUTH_KID 0x02

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* x5chain carries the full X.509 DER cert (384 B) inline in MSG_2/MSG_3 —
 * larger than the C509 c5c equivalent (~159 B). */
#define EDHOC_CONF_MAX_CRED_LEN 512
/* TH input = TH(34) + PLAINTEXT(ID_CRED x5chain map ~390 + Signature_or_MAC
 * 64 + CBOR overhead, ~460) + CRED(384) = ~847 bytes. */
#define EDHOC_CONF_MAX_BUFFER   1024
/* MSG_3 with inline client cert (384 B cert + signature + CBOR overhead). */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 512

/* MSG_2/MSG_3 are ~468 bytes (384-byte cert + signature + CBOR overhead) —
 * larger than the c5c equivalent (~242 bytes, fits a 256-byte block at
 * COAP_MAX_CHUNK_SIZE 300). Use 512 here so COAP_MAX_BLOCK_SIZE = 512 and
 * the whole message fits in a single CoAP block-wise transfer (must match
 * server). */
#define COAP_MAX_CHUNK_SIZE 512

/* Prevent competing EDHOC session from starting during MSG_2 transit. */
#undef  EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 1

/* --- Timing / RPL tuning — emulated vs real nRF52840 hardware ---
 * See edhoc-oscore-c5c-client/project-conf.h for the full rationale; the
 * larger X.509 DER cert (387 B vs ~159 B for c509 c5c) means more block-wise
 * CoAP fragments and longer radio-idle windows, so the same conservative
 * settings are kept (and COAP_RESPONSE_TIMEOUT is the same 15 s).
 *
 * RPL_MRHOF_CONF_MAX_LINK_METRIC 16384 (= ETX 128, default 512 = ETX 4):
 *   avoids RPL parent eviction during the transient NOACK burst on MSG_1.
 * RPL_MRHOF_CONF_MAX_PATH_COST 32768: paired with MAX_LINK_METRIC above.
 * RPL_CONF_PARENT_TIMEOUT 30: no-op — unused by RPL Lite OS sources. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */

/* OSCORE UDP port. */
#define OSCORE_UDP_PORT 5686

/* nRF52840: prevent deep power management so the radio stays responsive.
 * Required on real HW; also set in emulator for consistent behaviour. */
#define LPM_CONF_MAX_PM 1

/* EDHOC session watchdog: 100 s conservative for both emulated and real HW.
 * Reduce to ~30 s if tighter failure detection is needed on production HW. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
