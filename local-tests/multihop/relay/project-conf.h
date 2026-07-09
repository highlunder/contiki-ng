#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* A relay is never the RPL root -- it joins the DODAG as a router. */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 0
#endif

/* Forwarding-buffer headroom: a fragmented x5c certificate flight (~6 6LoWPAN
 * fragments) transits each relay, so the stock pools (per-neighbour TX queue,
 * inbound, and 6LoWPAN reassembly) must each hold a full flight or fragments
 * are dropped and the datagram lost -- the rxdiag lesson. */
#define QUEUEBUF_CONF_NUM                16
#define TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16
#define TSCH_CONF_MAX_INCOMING_PACKETS   8
#define SICSLOWPAN_CONF_FRAGMENT_BUFFERS 24

/* Match the endpoints' RPL link-metric tolerance so a transient multi-hop ETX
 * spike doesn't evict a parent mid-handshake. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

/* Multi-hop TSCH EB bootstrapping: on TSCH the per-node EB rate follows the RPL
 * DIO trickle (tsch_rpl_callback_new_dio_interval). The DEEPEST relay has no
 * children yet, so its trickle backs off fully and it nearly stops sending EBs
 * -- which is exactly the beacon the next node downstream needs to associate
 * (chicken-and-egg: it can't get a child until it beacons, won't beacon without
 * one). Capping the DIO interval keeps every joined relay beaconing (EB period is
 * upper-bounded by TSCH_MAX_EB_PERIOD=16 s anyway), so the chain can extend hop by
 * hop. DOUBLINGS=2 -> DIO max ~4.096 s x 2^2 = ~16 s. */
#define RPL_CONF_DIO_INTERVAL_DOUBLINGS 2

#define LOG_CONF_LEVEL_MAC LOG_LEVEL_WARN

#endif /* PROJECT_CONF_H_ */
