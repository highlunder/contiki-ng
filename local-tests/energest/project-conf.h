#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Firmware-side energy accounting on. */
#define ENERGEST_CONF_ON 1

/* Report every 20 s of sim time so a ~120 s run yields several steady-state
 * post-association periods. */
#define SIMPLE_ENERGEST_CONF_PERIOD (CLOCK_SECOND * 20)

/* ROOT=1 on the make line -> this image is the RPL root / TSCH coordinator;
 * otherwise a leaf. IS_NETWORK_ROUTING_ROOT is not self-defaulting, so define
 * it explicitly for both roles. */
#ifdef ENERGEST_ROLE_ROOT
#define IS_NETWORK_ROUTING_ROOT 1
#else
#define IS_NETWORK_ROUTING_ROOT 0
#endif

/* A little buffer headroom (harmless on CSMA; helps TSCH). */
#define QUEUEBUF_CONF_NUM 16

#endif /* PROJECT_CONF_H_ */
