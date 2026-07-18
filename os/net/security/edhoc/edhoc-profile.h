/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

/**
 * \file
 *   Lightweight, opt-in cycle profiling for the EDHOC crypto path.
 *
 *   Enabled by defining EDHOC_PROFILE_CYCLES (e.g. `EDHOC_PROFILE=1` in an
 *   app Makefile).  When undefined, every macro below compiles to nothing —
 *   zero cost, no behavioural change.
 *
 *   The cycle source is the ARM Cortex-M3/M4 Data Watchpoint & Trace (DWT)
 *   CYCCNT counter, accessed through raw register addresses so this header
 *   has no CMSIS / vendor-SDK dependency and can be included from the
 *   platform-agnostic EDHOC/COSE code.  CYCCNT increments once per core
 *   clock (64 MHz on nRF52840 => ~15.6 ns/tick), giving sub-microsecond
 *   per-operation resolution — far finer than rtimer/clock ticks, which is
 *   why it is used to isolate the cost of individual ECC operations (sign,
 *   verify, ECDH, key-gen) from surrounding network/protocol time.
 *
 *   NOTE: CYCCNT is a real-silicon facility.  Emulators (e.g. cooja-ng) need
 *   not model it; there the CYCCNT reads return 0.  To keep the profile useful
 *   in emulation too, every op is ALSO timed with the rtimer (which cooja-ng
 *   does model, cycle-accurately), reported in microseconds.  So on hardware
 *   the cycle count is the precise figure and the µs a cross-check; in the
 *   emulator the cycle count is 0 and the µs is the figure of record.  This is
 *   what lets us decompose the emulated handshake into crypto vs RF, and to
 *   separate the (emulated-nRF) responder's crypto — which on real hardware
 *   runs on a fast native x86 server and is ~free — from the client's.
 *
 *   Output format (one line per op, via printf so it does not depend on the
 *   including file's LOG_LEVEL):
 *     PROFILE <label>: <n> cycles <u> us
 */

#ifndef EDHOC_PROFILE_H_
#define EDHOC_PROFILE_H_

#include <stdint.h>

#ifdef EDHOC_PROFILE_CYCLES

#include <stdio.h>
#include "sys/rtimer.h"

/* ARM DWT / CoreDebug registers (raw addresses; no CMSIS dependency). */
#define EDHOC_DWT_CYCCNT     (*(volatile uint32_t *)0xE0001004UL)
#define EDHOC_DWT_CTRL       (*(volatile uint32_t *)0xE0001000UL)
#define EDHOC_CoreDebug_DEMCR (*(volatile uint32_t *)0xE000EDFCUL)
#define EDHOC_DEMCR_TRCENA    (1UL << 24)   /* enable trace/debug subsystem */
#define EDHOC_DWT_CYCCNTENA   (1UL << 0)    /* enable the cycle counter      */

/* Enable the DWT cycle counter.  Idempotent; call once at startup. */
static inline void
edhoc_profile_init(void)
{
  EDHOC_CoreDebug_DEMCR |= EDHOC_DEMCR_TRCENA;
  EDHOC_DWT_CYCCNT = 0;
  EDHOC_DWT_CTRL |= EDHOC_DWT_CYCCNTENA;
}

static inline uint32_t
edhoc_profile_now(void)
{
  return EDHOC_DWT_CYCCNT;
}

/* Capture both the DWT cycle count and the rtimer tick at once. */
#define EDHOC_PROFILE_DECL(var)                                       \
  uint32_t var = edhoc_profile_now();                                 \
  rtimer_clock_t var##_rt = RTIMER_NOW()
#define EDHOC_PROFILE_REPORT(var, label)                              \
  do {                                                                \
    uint32_t edhoc_profile_delta_ = edhoc_profile_now() - (var);      \
    rtimer_clock_t edhoc_profile_drt_ = RTIMER_NOW() - (var##_rt);    \
    uint32_t edhoc_profile_us_ =                                       \
      (uint32_t)(((uint64_t)edhoc_profile_drt_ * 1000000u)            \
                 / RTIMER_SECOND);                                    \
    printf("PROFILE %s: %lu cycles %lu us\n", (label),                \
           (unsigned long)edhoc_profile_delta_,                       \
           (unsigned long)edhoc_profile_us_);                         \
  } while(0)

#else /* !EDHOC_PROFILE_CYCLES */

static inline void edhoc_profile_init(void) { }
#define EDHOC_PROFILE_DECL(var)
#define EDHOC_PROFILE_REPORT(var, label)

#endif /* EDHOC_PROFILE_CYCLES */

#endif /* EDHOC_PROFILE_H_ */
