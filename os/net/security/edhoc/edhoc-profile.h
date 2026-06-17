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
 *   not model it; there the reads simply return 0 and the profile lines print
 *   "0 cycles" — harmless.  Use this for on-hardware measurement.
 *
 *   Output format (one line per op, via printf so it does not depend on the
 *   including file's LOG_LEVEL):
 *     PROFILE <label>: <n> cycles
 */

#ifndef EDHOC_PROFILE_H_
#define EDHOC_PROFILE_H_

#include <stdint.h>

#ifdef EDHOC_PROFILE_CYCLES

#include <stdio.h>

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

#define EDHOC_PROFILE_DECL(var)  uint32_t var = edhoc_profile_now()
#define EDHOC_PROFILE_REPORT(var, label)                              \
  do {                                                                \
    uint32_t edhoc_profile_delta_ = edhoc_profile_now() - (var);      \
    printf("PROFILE %s: %lu cycles\n",                                \
           (label), (unsigned long)edhoc_profile_delta_);             \
  } while(0)

#else /* !EDHOC_PROFILE_CYCLES */

static inline void edhoc_profile_init(void) { }
#define EDHOC_PROFILE_DECL(var)
#define EDHOC_PROFILE_REPORT(var, label)

#endif /* EDHOC_PROFILE_CYCLES */

#endif /* EDHOC_PROFILE_H_ */
