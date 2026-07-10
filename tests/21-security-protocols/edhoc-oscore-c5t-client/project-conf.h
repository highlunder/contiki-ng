#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* cooja-ng-ge derives node IPv6 from the emulated FICR (not the node id), so the
 * hard-coded EDHOC_CONF_SERVER_EP host never matches. Resolve the responder =
 * RPL DAG root dynamically instead (harmless on real RF: root == responder). */
#define EDHOC_CONF_SERVER_FROM_ROOT 1

/* Server address: node 2 in Cooja by default; override at build time
 * (-DEDHOC_CONF_SERVER_EP='"coap://[fd01::1]"') to target the native EDHOC
 * responder behind the Firefly gateway for real-RF OTA (see local-tests/). */
#ifndef EDHOC_CONF_SERVER_EP
#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"
#endif

/* EDHOC Method 0, C509 c5t (cert-hash-by-reference), initiator role. */
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

/* RFC 9529 C_I (initiator CID). */
#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_client_template.kid = 0x02). */
#define EDHOC_AUTH_KID 0x02

/* Cipher suite: secp256r1 + AES-CCM-16-64-128 + SHA-256. */
#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2

/* Enable Cryptographically Secure PRNG for ephemeral keys. */
#define CSPRNG_CONF_ENABLED 1

/* C509 cert is ~164 bytes; c5t MSG_2/MSG_3 carry cert hash not full cert. */
#define EDHOC_CONF_MAX_CRED_LEN 256
/* TH input = TH(34) + PLAINTEXT(~80) + CRED(~159) = ~273 bytes. */
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
#undef  EDHOC_CONF_ATTEMPTS
#define EDHOC_CONF_ATTEMPTS 4      /* E0 recovery hardening */
/* Multi-hop: the CoAP-CON forwarding of MSG_1/MSG_2 over several TSCH hops can take
 * >10 s (measured ~12 s at 2 hops), so a 10 s EDHOC watchdog makes the client
 * restart before the round trip completes. Give it per-hop headroom when built
 * multi-hop (MULTIHOP_CONNECT_DELAY_S>0); single-hop keeps the tight 10 s. */
#if defined(MULTIHOP_CONNECT_DELAY_S) && (MULTIHOP_CONNECT_DELAY_S > 0)
#define EDHOC_CONF_TIMEOUT 60000
/* THE multi-hop fix: when the client is >=2 hops from the coordinator its TSCH
 * time source is a relay, and the cooja-ng-ge emulator then reports a spurious
 * one-slotframe ASN drift on every EB, evicting the client every slotframe. It is
 * actually slot-aligned and communicating (handshakes complete once tolerated),
 * so relax the strict drift-leave here. Single-hop syncs to the coordinator and
 * never drifts, so this is a no-op there. See tsch-conf.h. */
#define TSCH_CONF_LEAVE_ON_ASN_DRIFT 0
/* The no-progress handshake deadline (edhoc-config.h default 12 s) is a SEPARATE
 * watchdog from EDHOC_CONF_TIMEOUT: it preempts a handshake that made no progress
 * within the deadline. Over multi-hop, forwarding MSG_1/MSG_2 across several TSCH
 * slotframes routinely exceeds 12 s, so the 12 s deadline fires mid-round-trip and
 * the client keeps preempting its own handshakes (the flaky-2-hop cause). Extend it
 * with the same per-hop headroom as the session timeout on multi-hop builds.
 * #undef first: edhoc-config.h may set the default (12) earlier in some units'
 * include order, so a bare #define would trip -Werror=redefined. */
#undef  EDHOC_CONF_HS_DEADLINE_SEC
#define EDHOC_CONF_HS_DEADLINE_SEC 150   /* generous: a clean 3-hop c5t handshake
   * already takes ~55 s (3 EDHOC messages x block-wise CoAP x 3-hop TSCH slotframe
   * forwarding), so keep well clear of the no-progress deadline. */
#else
#define EDHOC_CONF_TIMEOUT 10000  /* E0: was 100000 */
#endif

#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO


#endif /* PROJECT_CONF_H_ */
