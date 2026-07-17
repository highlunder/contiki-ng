#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Node role: the server is the RPL root + TSCH coordinator, the client is not.
 * Set by the Makefile (-DIS_NETWORK_ROUTING_ROOT=...). */
#ifndef IS_NETWORK_ROUTING_ROOT
#define IS_NETWORK_ROUTING_ROOT 0
#endif

/* Block-wise block size, and therefore the CoAP payload buffer. A power of two
 * in [16,1024] per RFC 7959. Default 64 keeps each block inside a single
 * 6LoWPAN frame, so the two arms differ in the NUMBER of block round-trips
 * rather than in per-block fragmentation -- isolating the size -> delivery
 * effect. Raise (e.g. CRL_BLOCK=256) to re-introduce fragmentation. */
#ifndef CRL_BLOCK
#define CRL_BLOCK 64
#endif
#define COAP_MAX_CHUNK_SIZE CRL_BLOCK

/* NB: COAP_RESPONSE_TIMEOUT / COAP_MAX_RETRANSMIT are raised for multi-hop in
 * the Makefile (-D), not here: coap-constants.h is included ahead of
 * project-conf.h in the coap TUs, so a definition here would be a redefinition
 * rather than an override. */

/* Buffer sizing is deliberately left at the stack defaults, matching the M1
 * endpoints. Raising QUEUEBUF_CONF_NUM to 16 *with* an equal per-neighbour
 * bound lets a single neighbour consume every queuebuf, after which broadcast
 * (EB/DIO) can no longer be queued and the node wedges -- observed here as
 * "can't send packet to ffff.ffff.ffff.ffff, queue 16/16" with not one CoAP
 * packet ever transmitted. Only the relay carries enlarged buffers (it forwards
 * for others; see relay/project-conf.h). */

/* The knobs below apply only to a node that HAS a parent and a TSCH time source.
 * The root/coordinator has neither, and the M1 server (the known-good reference
 * for this topology) sets none of them. Applying them to the root demonstrably
 * breaks the network two hops out: the client associates, joins, and then goes
 * both deaf and mute a few seconds later, idling in platform_idle with no
 * scheduled wakeup, while the relay next to it keeps beaconing. Keep the root's
 * configuration minimal. */
#if !IS_NETWORK_ROUTING_ROOT

/* NB: LPM_CONF_MAX_PM is deliberately NOT set. The M1 configs carry it, but it
 * is a knob of the deprecated arch/platform/nrf52840 tree -- it does not exist
 * anywhere under arch/{cpu,platform}/nrf, so on the shared platform we build for
 * it is inert. Setting it here would only imply a control we do not have. */

/* Don't let a transient multi-hop ETX spike evict a parent mid-transfer. */
#define RPL_MRHOF_CONF_MAX_LINK_METRIC 16384
#define RPL_MRHOF_CONF_MAX_PATH_COST   32768

/* NB: RPL_CONF_DIO_INTERVAL_DOUBLINGS is deliberately NOT set here. It is a
 * relay-only knob (see relay/project-conf.h): it caps the DIO trickle so a
 * joined relay keeps beaconing for the next hop. On an endpoint it only makes
 * the node emit multicast DIOs faster than TSCH's shared broadcast slot can
 * drain them; the queued DIOs then consume the whole global queuebuf pool
 * (observed: "queue 1/8 8/8" with 6 packets stuck in the broadcast queue) and
 * the application can no longer enqueue a single CoAP request. The M1 endpoints
 * likewise leave the trickle at its default. */

/* THE multi-hop fix (see relay/project-conf.h + tsch-conf.h): tolerate the
 * emulator's spurious one-slotframe ASN-drift detection, else the network
 * silently caps at a single hop. */
#define TSCH_CONF_LEAVE_ON_ASN_DRIFT 0

#endif /* !IS_NETWORK_ROUTING_ROOT */

/* Build with CRL_DIAG=1 to see TSCH association + RPL parent selection; the
 * default keeps the logs small enough to parse quickly. */
#ifdef CRL_DIAG
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_INFO
#else
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_WARN
#endif

#endif /* PROJECT_CONF_H_ */
