#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja. */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 0, X.509 x5chain (cert inline delivery), initiator role. */
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_X509_X5C

/* RFC 9529 C_I (initiator CID). */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_x509_chain2_client_template.kid = 0x54). */
#define EDHOC_AUTH_KID 0x54

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* Chain-length-2 x5chain: CRED_x = [bstr<leaf 383/384B>, bstr<Sub CA 2 397B>,
 * bstr<Sub CA 1 397B>] = 1188 B, ID_CRED_x = {33: <1188 B array>} = ~1191 B.
 * Sized to 1280 with margin. */
#define EDHOC_CONF_MAX_CRED_LEN    1280
#define EDHOC_CONF_MAX_ID_CRED_LEN 1280
/* TH input = TH-bstr(34) + PLAINTEXT_3(~1257, incl. ID_CRED_I ~1191 +
 * Signature_or_MAC_3 ~66) + CRED(~1190) = ~2481 bytes. Sized to 2688 with
 * margin. */
#define EDHOC_CONF_MAX_BUFFER      2688
/* MSG_2/MSG_3 with inline 3-cert X.509 chain (~1290 B incl. AEAD tag). */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 1536

/* Must be a power of two (CoAP block SZX encoding): 16/32/.../1024. Must
 * match server. See edhoc-oscore-x509-chain-client/project-conf.h. */
#define COAP_MAX_CHUNK_SIZE 256

/* Prevent competing EDHOC session from starting during MSG_2 transit. */
#undef  EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 1

/* --- Timing / RPL tuning — emulated vs real nRF52840 hardware ---
 * See edhoc-oscore-x509-chain-client/project-conf.h for the full rationale;
 * the 3-cert X.509 chain inline delivery (1188 B CRED_x) is larger than
 * chain-length-1 X.509 (782 B), so the same generous margins are kept (and
 * COAP_RESPONSE_TIMEOUT raised further in Makefile).
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

/* EDHOC session watchdog: 100 s conservative for both emulated and real HW. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
