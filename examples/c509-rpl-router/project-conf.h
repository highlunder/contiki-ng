#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- Logging ---- */
#define LOG_CONF_LEVEL_RPL      LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_IPV6     LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_6LOWPAN  LOG_LEVEL_WARN

/* ---- 6LoWPAN / routing ----
 * Larger queuebuf for multi-hop forwarding: intermediate nodes buffer
 * fragments from both directions simultaneously. */
#define QUEUEBUF_CONF_NUM 24

/* ---- RPL ----
 * Same parent-timeout and link-metric tuning as the client node so the
 * whole mesh uses consistent parameters. */
#define RPL_CONF_PARENT_TIMEOUT        30
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

/* ---- CSMA ---- */
#define CSMA_CONF_MAX_TX_RETRIES 3

/* ---- Platform ---- */
#define LPM_CONF_ENABLE 0
#define NRF52840_CCA_TIMEOUT_ITERATIONS 1000UL

#endif /* PROJECT_CONF_H_ */
