/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * nRF52840-DK bring-up rung 2: board health.
 *
 * Validates, with no network and no crypto:
 *   - the firmware boots and reaches main(),
 *   - the SEGGER VCP UART console prints,
 *   - the clock / etimer fires once per second,
 *   - GPIO works (the four user LEDs toggle each tick).
 *
 * Expected console output (one line per second):
 *   uptime: 1 s
 *   uptime: 2 s
 *   ...
 * and the LEDs visibly toggle.
 */

#include "contiki.h"
#include "dev/leds.h"
#include <stdio.h>
#include <stdint.h>

PROCESS(board_check_process, "Board check");
AUTOSTART_PROCESSES(&board_check_process);

PROCESS_THREAD(board_check_process, ev, data)
{
  static struct etimer et;
  static uint32_t secs;

  PROCESS_BEGIN();

  printf("\n=== nRF52840-DK board check ===\n");
  printf("UART console OK if you can read this.\n");
  printf("Expect one tick per second; LEDs toggle each tick.\n");

  etimer_set(&et, CLOCK_SECOND);
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));
    etimer_reset(&et);
    secs++;
    leds_toggle(LEDS_ALL);
    printf("uptime: %lu s\n", (unsigned long)secs);
  }

  PROCESS_END();
}
