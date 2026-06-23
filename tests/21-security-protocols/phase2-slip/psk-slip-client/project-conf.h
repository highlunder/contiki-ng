/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * All rights reserved.
 *
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */
#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* ---- DTLS / PSK (same as psk-native-dtls-client) ---- */
#define LOG_CONF_LEVEL_APP  LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_DTLS LOG_LEVEL_DBG
#define WITH_DTLS                   1
#define COAP_DTLS_CONF_WITH_PSK     1
#define COAP_DTLS_CONF_WITH_CLIENT  1
#define HEAPMEM_CONF_ARENA_SIZE (32 * 1024)
#define MBEDTLS_SSL_MAX_CONTENT_LEN     4096
#define MBEDTLS_KEY_EXCHANGE_PSK_ENABLED
#define COAP_MAX_CHUNK_SIZE 300
#define CSPRNG_CONF_ENABLED 1
#define QUEUEBUF_CONF_NUM 16

/*
 * ---- Phase-2 single-board SLIP uplink (no second radio) ----
 *
 * The data path (SLIP) and the console (logs) must not share one serial line,
 * or interleaved log bytes corrupt SLIP framing. We split them across the
 * DK's two USB serials:
 *   - SLIP  -> UART0, the always-present J-Link VCOM (host /dev/ttyACM*, the
 *              one tunslip6 attaches to). Reliable, so it carries the data.
 *   - logs  -> nRF native USB CDC (a second /dev/ttyACM*), for observation
 *              (board-side PASS marker). The test still passes on the server
 *              side even if the log port is not captured.
 *
 * Alternatives (see PHASE2-SLIP-README.md): SLIP on the nRF native USB with
 * logs on the VCOM UART (SLIP_ARCH_CONF_USB=1, DBG_CONF_USB=0); or logs over
 * SEGGER RTT if the RTT sources are vendored for this CPU.
 */
/* NRF52840_NATIVE_USB=1 is set in the Makefile (it gates the USB sources and
 * -D's the macro). Here we only steer which peripheral each stream uses: */
#define DBG_CONF_USB        1   /* console logs -> nRF native USB CDC */
#define SLIP_ARCH_CONF_USB  0   /* SLIP -> UART0 (J-Link VCOM) */

/*
 * ---- setest server location (as seen from the board) ----
 * With `tunslip6 -s <serial> fd00::1/64` the host tun endpoint is fd00::1;
 * setest binds there (or on ::). Port is the scenario's setest port
 * (psk -> 5686). Consumed by psk-slip-client.c.
 */
#ifndef PHASE2_SERVER_ADDR
#define PHASE2_SERVER_ADDR "fd00::1"
#endif
#ifndef PHASE2_SERVER_PORT
#define PHASE2_SERVER_PORT 5686
#endif

#endif /* PROJECT_CONF_H_ */
