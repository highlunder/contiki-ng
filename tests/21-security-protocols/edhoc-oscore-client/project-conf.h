#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Server address: node 2 in Cooja (same as existing EDHOC tests). */
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* EDHOC Method 0 (Sig|Sig) with KID credentials, initiator role. */
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_KID

/* RFC 9529 C_I (initiator CID) = -24 in CBOR encoding. */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_rfc9529_static_dh_client.kid = 0x2b). */
#define EDHOC_AUTH_KID 0x2b

/* Cipher suites supported (suite 2 = secp256r1 + AES-CCM-16-64-128 + SHA-256). */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define EDHOC_CONF_SUPPORTED_SUITE_2 EDHOC_CIPHERSUITE_6

/* Enable Cryptographically Secure PRNG for EDHOC ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* OSCORE UDP port (separate from CoAP 5683 and DTLS 5684). */
#define OSCORE_UDP_PORT 5686

/* Enough buffer for OSCORE exchange. */
#define EDHOC_CONF_MAX_PAYLOAD_LEN 256
#define EDHOC_CONF_MAX_BUFFER      256

/* --- Timing / RPL tuning — emulated vs real nRF52840 hardware ---
 *
 * COAP_RESPONSE_TIMEOUT (set in Makefile to 15 s, default 3 s):
 *   Keep 15 s in both environments.  A SEQUENCE_ERROR on MSG_1 triggers a
 *   second round trip; combined with 802.15.4 fragmentation of MSG_2, the
 *   default 3 s is too short in either case.  On a clean physical link
 *   5–8 s would suffice, but 15 s is a safe conservative choice.
 *
 * EDHOC_CONF_TIMEOUT (100 000 ms = 100 s):
 *   nRF52840 P256 ECDH takes ~300 ms real time; full handshake ≤ 5 s real.
 *   Same value works for emulator and real hardware — the timer uses
 *   CLOCK_SECOND so it measures simulated time on both.  Could be reduced
 *   to 30 s on real hardware; 100 s is conservative.
 *
 * LPM_CONF_MAX_PM 1:
 *   Real HW: keeps nRF52840 in light sleep (PM1) so the radio can wake
 *   quickly; deep sleep (PM2+) would cause the node to miss incoming frames
 *   during ECDH computation.  Emulator: no power model, but consistent.
 *
 * RPL_MRHOF_CONF_MAX_LINK_METRIC 16384 (= ETX 128, default 512 = ETX 4):
 *   Emulator: the first MSG_1 suffers a transient burst of 8 MAC NACKs
 *   (radio-alignment timing artefact), raising the RPL link-quality ETX to
 *   ~832.  rpl_dag_update_state() then evicts the preferred parent and
 *   node_is_reachable() returns 0, causing MSG_3 to be silently dropped by
 *   coap_endpoint_is_connected() with no log.  Raising the threshold keeps
 *   the parent alive until the link recovers.
 *   Real HW: not strictly needed on a clean link (typical ETX 1–2), but
 *   safe to keep for robustness against transient link degradation.
 *
 * RPL_MRHOF_CONF_MAX_PATH_COST 32768: paired with MAX_LINK_METRIC above.
 *
 * RPL_CONF_PARENT_TIMEOUT 30: defined for documentation purposes only —
 *   this symbol is not referenced in RPL Lite OS sources and has no runtime
 *   effect. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */

/* nRF52840: prevent deep power management so the radio stays responsive.
 * Required on real HW; also set in emulator for consistent behaviour. */
#define LPM_CONF_MAX_PM 1

/* EDHOC session watchdog.  nRF52840 P256 ECDH takes ~300 ms real time;
 * 100 s is conservative for both emulated and real hardware.  Reduce to
 * ~30 s if tighter failure detection is needed on production hardware. */
#define EDHOC_CONF_TIMEOUT 100000

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

#endif /* PROJECT_CONF_H_ */
