/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * nRF52840-DK micro-benchmark: SOFTWARE X25519 (ECDH) + Ed25519 (EdDSA),
 * the software counterpart to ec25519-bench (which runs the same primitives on
 * the CC310 accelerator).  Together they give the hardware-vs-software speedup
 * for the Curve25519/Ed25519 family, mirroring what ecc-bench gives for P-256.
 *
 * Software backend: Monocypher (portable, public-domain) -- crypto_x25519* for
 * Curve25519 ECDH and the optional SHA-512 module for standard RFC 8032
 * Ed25519.  Same DWT cycle-counter + summary harness and op layout as
 * ec25519-bench, so the rows line up directly.
 *
 * Build:
 *   make TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR=
 *
 * A green LED + "RESULT: PASS" means every op succeeded, ECDH(a,B)==ECDH(b,A),
 * and each Ed25519 signature verified.
 */

#include "contiki.h"
#include "dev/watchdog.h"
#include "dev/leds.h"
#include "lib/random.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#define ECC_BENCH_BACKEND "software (Monocypher)"

/* Firmware build id, stamped into the SUMMARY line for traceability (matches the
 * ecc-bench / enroll-ops convention). Override with FW_ID=<id> at build; the
 * Makefile passes it through as -DFW_BUILD_ID. */
#ifndef FW_BUILD_ID
#define FW_BUILD_ID "unstamped"
#endif

#define CPU_HZ        64000000UL
#ifndef BENCH_ITERS
#define BENCH_ITERS   100
#endif
#define ED_MSGLEN     32

#ifndef ECC_BENCH_DEBUG
#define ECC_BENCH_DEBUG 0
#endif

#if ECC_BENCH_DEBUG
#define DBG_BEFORE(lbl)        printf("[i=%d] %-11s start...\n", i, (lbl))
#define DBG_AFTER(lbl, c, r)   printf("[i=%d] %-11s done res=%d %lu cyc\n", \
                                      i, (lbl), (r), (unsigned long)(c))
#define PROG_DOT()
#define PROG_TICK(n)
#else
#define DBG_BEFORE(lbl)
#define DBG_AFTER(lbl, c, r)
#define PROG_DOT()             putchar('.')
#define PROG_TICK(n)           do {                                          \
                                 if(((n) + 1) % 10 == 0) {                   \
                                   printf(" %d/%d\n", (n) + 1, BENCH_ITERS); \
                                 }                                           \
                               } while(0)
#endif

#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004UL)
#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000UL)
#define DEMCR      (*(volatile uint32_t *)0xE000EDFCUL)

static inline void
dwt_init(void)
{
  DEMCR |= (1UL << 24);
  DWT_CYCCNT = 0;
  DWT_CTRL |= 1UL;
}
static inline uint32_t
dwt_now(void)
{
  return DWT_CYCCNT;
}

static uint32_t
isqrt64(uint64_t v)
{
  uint64_t op = v, res = 0, one = 1ULL << 62;
  while(one > op) {
    one >>= 2;
  }
  while(one != 0) {
    if(op >= res + one) {
      op -= res + one;
      res += one << 1;
    }
    res >>= 1;
    one >>= 2;
  }
  return (uint32_t)res;
}

static void
fill_random(uint8_t *p, unsigned n)
{
  unsigned k;
  for(k = 0; k < n; k++) {
    p[k] = (uint8_t)random_rand();
  }
}

enum {
  OP_X_KG_A, OP_X_KG_B, OP_X_ECDH_AB, OP_X_ECDH_BA,
  OP_E_KG, OP_E_SIGN, OP_E_VERIFY, N_OPS
};

struct op_group {
  const char *name;
  uint8_t op0;
  uint8_t op1;
  uint8_t nop;
};
static const struct op_group op_groups[] = {
  { "x25519-keygen",  OP_X_KG_A,    OP_X_KG_B,    2 },
  { "x25519-ecdh",    OP_X_ECDH_AB, OP_X_ECDH_BA, 2 },
  { "ed25519-keygen", OP_E_KG,      OP_E_KG,      1 },
  { "ed25519-sign",   OP_E_SIGN,    OP_E_SIGN,    1 },
  { "ed25519-verify", OP_E_VERIFY,  OP_E_VERIFY,  1 },
};
#define N_GROUPS (sizeof(op_groups) / sizeof(op_groups[0]))

/* rc = (expr).  void Monocypher calls use the comma operator: (call, 0). */
#define TIME_OP(slot, label, expr)                           \
  do {                                                       \
    DBG_BEFORE(label);                                       \
    t = dwt_now();                                           \
    rc = (expr);                                             \
    cyc = dwt_now() - t;                                     \
    cyc_log[i][slot] = cyc;                                  \
    res_log[i][slot] = rc;                                   \
    if(rc != 0) {                                            \
      ok = false;                                            \
    }                                                        \
    DBG_AFTER(label, cyc, rc);                               \
    watchdog_periodic();                                     \
    PROG_DOT();                                              \
  } while(0)

PROCESS(ec25519_sw_bench_process, "EC25519 sw benchmark");
AUTOSTART_PROCESSES(&ec25519_sw_bench_process);

PROCESS_THREAD(ec25519_sw_bench_process, ev, data)
{
  static struct etimer et;
  static uint8_t xpriv_a[32], xpub_a[32], xpriv_b[32], xpub_b[32];
  static uint8_t xsec_a[32], xsec_b[32];
  static uint8_t eseed[32], esk[64], epk[32], emsg[ED_MSGLEN], esig[64];
  static uint32_t t, cyc;
  static int i, rc;
  static bool ok = true;
  static bool x_match[BENCH_ITERS];
  static uint32_t cyc_log[BENCH_ITERS][N_OPS];
  static int res_log[BENCH_ITERS][N_OPS];
  static unsigned g, k, op, n_samp, fails;
  static uint32_t c, mn, mx, mean_cyc, sd_cyc;
  static uint64_t sum, sumsq, var;

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND * 2);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  printf("\n=== nRF52840 EC25519 benchmark (X25519 + Ed25519) ===\n");
  printf("backend: %s\n", ECC_BENCH_BACKEND);
  /* Report (do not set) the NVMC I-cache state: the platform enables it in
   * platform_init_stage_one() from 2026-07-17, so a fresh build runs cache-ON.
   * Monocypher is portable C (no ARM asm), hence flash-fetch-bound and
   * cache-sensitive -- so this line matters for interpreting the numbers. */
  printf("NVMC I-cache: %s\n",
         ((*(volatile uint32_t *)0x4001E540UL) & 1UL) ? "ENABLED" : "disabled");

  dwt_init();
  t = dwt_now();
  clock_delay_usec(1000);
  cyc = dwt_now() - t;
  printf("DWT sanity: 1 ms delay measured %lu cyc (expect ~%lu)\n",
         (unsigned long)cyc, (unsigned long)(CPU_HZ / 1000UL));

  memset(emsg, 0xA5, sizeof(emsg));

  for(i = 0; i < BENCH_ITERS; i++) {
    /* ---- X25519: two key pairs + ECDH both directions ---- */
    fill_random(xpriv_a, 32);
    TIME_OP(OP_X_KG_A, "x25519-kgA",
            (crypto_x25519_public_key(xpub_a, xpriv_a), 0));
    fill_random(xpriv_b, 32);
    TIME_OP(OP_X_KG_B, "x25519-kgB",
            (crypto_x25519_public_key(xpub_b, xpriv_b), 0));

    TIME_OP(OP_X_ECDH_AB, "x25519-aB",
            (crypto_x25519(xsec_a, xpriv_a, xpub_b), 0));
    TIME_OP(OP_X_ECDH_BA, "x25519-bA",
            (crypto_x25519(xsec_b, xpriv_b, xpub_a), 0));

    x_match[i] = (memcmp(xsec_a, xsec_b, 32) == 0);
    if(!x_match[i]) {
      ok = false;
    }

    /* ---- Ed25519: keygen (from seed), sign, verify ---- */
    fill_random(eseed, 32);
    TIME_OP(OP_E_KG, "ed25519-kg",
            (crypto_ed25519_key_pair(esk, epk, eseed), 0));
    TIME_OP(OP_E_SIGN, "ed25519-sg",
            (crypto_ed25519_sign(esig, esk, emsg, sizeof(emsg)), 0));
    TIME_OP(OP_E_VERIFY, "ed25519-vf",
            crypto_ed25519_check(esig, epk, emsg, sizeof(emsg)));

    PROG_TICK(i);
  }

  printf("\n=== SUMMARY (X25519 + Ed25519, %s, %d iters, fw %s) ===\n",
         ECC_BENCH_BACKEND, BENCH_ITERS, FW_BUILD_ID);
  printf("op              n  nfail   min_us   mean_us    max_us    sd_us\n");
  for(g = 0; g < N_GROUPS; g++) {
    sum = 0;
    sumsq = 0;
    mn = 0xFFFFFFFFUL;
    mx = 0;
    n_samp = 0;
    fails = 0;
    for(i = 0; i < BENCH_ITERS; i++) {
      for(k = 0; k < (unsigned)op_groups[g].nop; k++) {
        op = (k == 0) ? op_groups[g].op0 : op_groups[g].op1;
        c = cyc_log[i][op];
        sum += c;
        sumsq += (uint64_t)c * c;
        if(c < mn) {
          mn = c;
        }
        if(c > mx) {
          mx = c;
        }
        if(res_log[i][op] != 0) {
          fails++;
        }
        n_samp++;
      }
    }
    mean_cyc = (uint32_t)(sum / n_samp);
    var = (sumsq - sum * sum / n_samp) / n_samp;
    sd_cyc = isqrt64(var);
    printf("%-14s %3u  %5u  %8lu  %8lu  %8lu  %8lu\n",
           op_groups[g].name, n_samp, fails,
           (unsigned long)(mn / (CPU_HZ / 1000000UL)),
           (unsigned long)(mean_cyc / (CPU_HZ / 1000000UL)),
           (unsigned long)(mx / (CPU_HZ / 1000000UL)),
           (unsigned long)(sd_cyc / (CPU_HZ / 1000000UL)));
  }

  printf("\n=== RESULT: %s (%s) ===\n", ok ? "PASS" : "FAIL", ECC_BENCH_BACKEND);
  leds_on(ok ? LEDS_GREEN : LEDS_RED);

  PROCESS_END();
}
