#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define EDHOC_CONF_SERVER_EP "coap://[fd00::202:2:2:2]"

/* cooja-ng-ge derives node IPv6 from the emulated FICR (not the node id), so the
 * hard-coded EDHOC_CONF_SERVER_EP host never matches. Resolve the CA/responder =
 * RPL DAG root dynamically instead (harmless on real RF: root == responder). */
#define EDHOC_CONF_SERVER_FROM_ROOT 1

/* EDHOC Method 0, C509 c5t (cert-hash-by-reference), initiator role. */
#define EDHOC_CONF_ROLE         EDHOC_INITIATOR
#define EDHOC_CONF_AUTHENT_TYPE EDHOC_CRED_C509_C5T

#define EDHOC_CONF_CID 0x37

/* Own authentication KID (matches auth_c509_native_client_template.kid = 0x03). */
#define EDHOC_AUTH_KID 0x03

#define EDHOC_CONF_SUPPORTED_SUITE_1 EDHOC_CIPHERSUITE_2
#define CSPRNG_CONF_ENABLED 1

#define EDHOC_CONF_MAX_CRED_LEN 256
#define EDHOC_CONF_MAX_BUFFER   384
#define COAP_MAX_CHUNK_SIZE 300

/* RPL tuning: avoids parent eviction from the transient ETX spike on the
 * first MSG_1 NOACK burst, matching the working native-pairing config
 * logged in cooja-ng/test-runs/TEST-LOG.md. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768
#define RPL_CONF_PARENT_TIMEOUT        30  /* no-op: unused by RPL Lite */

#define OSCORE_UDP_PORT 5686

/* Keep the radio responsive during ECDH on real HW; harmless in emulation. */
#define LPM_CONF_MAX_PM 1

/* EDHOC handshake watchdog + inter-attempt backoff base (ms). Was 100000 (100 s),
 * which made both the coap_timer watchdog and the retry backoff too long to recover
 * within a run budget under loss (restart-on-failure Phase 2.5). 10 s is above the
 * bounded CoAP give-up (~9 s) so it only catches true stalls; the backoff is capped
 * low so several attempts fit the budget. */
#define EDHOC_CONF_TIMEOUT 10000
#define LOG_CONF_LEVEL_EDHOC LOG_LEVEL_INFO

/* Multi-hop over TSCH (built with MULTIHOP_CONNECT_DELAY_S>0): tolerate the
 * emulator's spurious one-slotframe ASN-drift eviction so a relay-sourced node stays
 * associated (see tsch-conf.h), and give the EDHOC handshake's no-progress deadline
 * per-hop headroom. Single-hop syncs to the coordinator -> no-op. */
#if defined(MULTIHOP) && MULTIHOP
#define TSCH_CONF_LEAVE_ON_ASN_DRIFT 0
#undef  EDHOC_CONF_TIMEOUT
#define EDHOC_CONF_TIMEOUT 60000
#undef  EDHOC_CONF_HS_DEADLINE_SEC
#define EDHOC_CONF_HS_DEADLINE_SEC 150
#endif

#endif /* PROJECT_CONF_H_ */
