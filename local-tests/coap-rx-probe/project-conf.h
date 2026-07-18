/*
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * coap-rx-probe sender config: match the cert-DTLS bench / border-router TSCH +
 * 6LoWPAN buffer provisioning and RPL tuning so the large-datagram probe uses
 * the SAME transport the benches use (TSCH-gated).
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO

/* Hold a full multi-fragment datagram on transmit (matches the border-router). */
#define QUEUEBUF_CONF_NUM 24

/* RPL parent-eviction guard (match the benches). */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

/* TSCH buffer over-provisioning (match dtls-x509-bench). TSCH-gated. */
#if MAC_CONF_WITH_TSCH
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16
#define TSCH_CONF_MAX_INCOMING_PACKETS   8
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 24
#endif /* MAC_CONF_WITH_TSCH */

#endif /* PROJECT_CONF_H_ */
