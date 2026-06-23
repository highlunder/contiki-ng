/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * nRF52840-DK micro-benchmark: Curve25519 (X25519 ECDH) + Ed25519 (EdDSA),
 * the EDHOC cipher-suite 0/1/4 key-establishment + authentication primitives,
 * on the CC310 hardware accelerator.  Companion to ecc-bench (secp256r1 /
 * brainpoolP256r1), using the SAME DWT cycle-counter + summary harness so the
 * two are directly comparable.
 *
 * Why a separate app: X25519/Ed25519 do NOT flow through lib/ecc.h (which is
 * curve/ECDSA-shaped).  We call nrf_crypto directly with the curve25519 /
 * ed25519 curve_info, mirroring the call patterns in
 * arch/cpu/nrf52840/dev/nrf52840-cc310-ecc.c.  We still reuse that backend's
 * ecc_init() (nrf_crypto_init) and ecc_session_begin()/_end() so the one-time
 * CC310 TRNG seeding runs inside the BASEPRI-isolated critical section
 * (otherwise the 128 Hz RTC tick breaks the TRNG startup test -- see the
 * backend file / PLAN-c509-lice-followup.md Sec. 9.11).
 *
 * Build (no software counterpart: uECC has no 25519; that path would be a
 * separate mbedTLS/ed25519_verify bench):
 *   make TARGET=nrf52840 BOARD=dk ECC_HW_BACKEND=cc310 CC310_ECC_25519=1
 *
 * A green LED + "RESULT: PASS" means every op returned success, ECDH(a,B) ==
 * ECDH(b,A), and each Ed25519 signature verified.
 */

#include "contiki.h"
#include "dev/watchdog.h"
#include "dev/leds.h"
#include "lib/ecc.h"                 /* ecc_init / ecc_session_begin / _end */
#include "nrf_crypto_init.h"
#include "nrf_crypto_ecc.h"
#include "nrf_crypto_ecdh.h"
#include "nrf_crypto_eddsa.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#define ECC_BENCH_BACKEND "CC310 hardware"

#define CPU_HZ        64000000UL   /* nRF52840 core clock */
#ifndef BENCH_ITERS
#define BENCH_ITERS   100          /* override from Makefile: ITERS=<n> */
#endif

#define X25519_SECRET   NRF_CRYPTO_ECDH_CURVE25519_SHARED_SECRET_SIZE  /* 32 */
#define ED25519_SIG     NRF_CRYPTO_EDDSA_ED25519_SIGNATURE_SIZE        /* 64 */
#define ED25519_MSGLEN  32

#ifndef ECC_BENCH_VERBOSE
#define ECC_BENCH_VERBOSE 0
#endif
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
/* Non-intrusive progress: one dot per op + a counter every 10 iterations,
 * printed between ops (outside the timed window). */
#define PROG_DOT()             putchar('.')
#define PROG_TICK(n)           do {                                          \
                                 if(((n) + 1) % 10 == 0) {                   \
                                   printf(" %d/%d\n", (n) + 1, BENCH_ITERS); \
                                 }                                           \
                               } while(0)
#endif

/* --- self-contained ARM Cortex-M DWT cycle counter (raw regs, no CMSIS) --- */
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004UL)
#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000UL)
#define DEMCR      (*(volatile uint32_t *)0xE000EDFCUL)

static inline void
dwt_init(void)
{
  DEMCR |= (1UL << 24);   /* TRCENA */
  DWT_CYCCNT = 0;
  DWT_CTRL |= 1UL;        /* CYCCNTENA */
}
static inline uint32_t
dwt_now(void)
{
  return DWT_CYCCNT;
}

/* Integer sqrt (no FPU / no float printf needed) for the std-dev column. */
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

/* Per-op slots.  x25519-keygen/ecdh run twice (two key pairs), pooled in the
 * summary; ed25519 keygen/sign/verify run once each. */
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
  { "x25519-keygen", OP_X_KG_A,    OP_X_KG_B,    2 },
  { "x25519-ecdh",   OP_X_ECDH_AB, OP_X_ECDH_BA, 2 },
  { "ed25519-keygen", OP_E_KG,     OP_E_KG,      1 },
  { "ed25519-sign",  OP_E_SIGN,    OP_E_SIGN,    1 },
  { "ed25519-verify", OP_E_VERIFY, OP_E_VERIFY,  1 },
};
#define N_GROUPS (sizeof(op_groups) / sizeof(op_groups[0]))

/* Time one nrf_crypto call.  Nothing prints inside the dwt_now() window;
 * `expr` must evaluate to a ret_code_t (NRF_SUCCESS == 0). */
#define TIME_OP(slot, label, expr)                           \
  do {                                                       \
    DBG_BEFORE(label);                                       \
    t = dwt_now();                                           \
    ret = (expr);                                            \
    cyc = dwt_now() - t;                                     \
    cyc_log[i][slot] = cyc;                                  \
    res_log[i][slot] = (int)ret;                             \
    if(ret != NRF_SUCCESS) {                                 \
      ok = false;                                            \
    }                                                        \
    DBG_AFTER(label, cyc, (int)ret);                         \
    watchdog_periodic();                                     \
    PROG_DOT();                                              \
  } while(0)

PROCESS(ec25519_bench_process, "EC25519 benchmark");
AUTOSTART_PROCESSES(&ec25519_bench_process);

PROCESS_THREAD(ec25519_bench_process, ev, data)
{
  static struct etimer et;
  static nrf_crypto_ecc_private_key_t xpriv_a, xpriv_b, epriv;
  static nrf_crypto_ecc_public_key_t  xpub_a, xpub_b, epub;
  static uint8_t xsec_a[X25519_SECRET], xsec_b[X25519_SECRET];
  static uint8_t emsg[ED25519_MSGLEN], esig[ED25519_SIG];
  static size_t n1, n2, eslen;
  static ret_code_t ret;
  static uint32_t t, cyc;
  static int i;
  static bool ok = true;
  static uint32_t cyc_log[BENCH_ITERS][N_OPS];
  static int res_log[BENCH_ITERS][N_OPS];
  static bool x_match[BENCH_ITERS];
  /* summary accumulators */
  static unsigned g, k, op, n_samp, fails;
  static uint32_t c, mn, mx, mean_cyc, sd_cyc;
  static uint64_t sum, sumsq, var;

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND * 2);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  printf("\n=== nRF52840 EC25519 benchmark (X25519 + Ed25519) ===\n");
  printf("backend: %s\n", ECC_BENCH_BACKEND);

  dwt_init();
  t = dwt_now();
  clock_delay_usec(1000);
  cyc = dwt_now() - t;
  printf("DWT sanity: 1 ms delay measured %lu cyc (expect ~%lu)\n",
         (unsigned long)cyc, (unsigned long)(CPU_HZ / 1000UL));

  memset(emsg, 0xA5, sizeof(emsg));

  ecc_init();             /* nrf_crypto_init() */
  ecc_session_begin();    /* BASEPRI-isolated CC310 TRNG seeding */

  for(i = 0; i < BENCH_ITERS; i++) {
    /* ---- X25519: two key pairs + ECDH both directions ---- */
    TIME_OP(OP_X_KG_A, "x25519-kgA",
            nrf_crypto_ecc_key_pair_generate(
              NULL, &g_nrf_crypto_ecc_curve25519_curve_info, &xpriv_a, &xpub_a));
    TIME_OP(OP_X_KG_B, "x25519-kgB",
            nrf_crypto_ecc_key_pair_generate(
              NULL, &g_nrf_crypto_ecc_curve25519_curve_info, &xpriv_b, &xpub_b));

    n1 = X25519_SECRET;
    TIME_OP(OP_X_ECDH_AB, "x25519-aB",
            nrf_crypto_ecdh_compute(NULL, &xpriv_a, &xpub_b, xsec_a, &n1));
    n2 = X25519_SECRET;
    TIME_OP(OP_X_ECDH_BA, "x25519-bA",
            nrf_crypto_ecdh_compute(NULL, &xpriv_b, &xpub_a, xsec_b, &n2));

    x_match[i] = (memcmp(xsec_a, xsec_b, X25519_SECRET) == 0);
    if(!x_match[i]) {
      ok = false;
    }

    nrf_crypto_ecc_private_key_free(&xpriv_a);
    nrf_crypto_ecc_private_key_free(&xpriv_b);
    nrf_crypto_ecc_public_key_free(&xpub_a);
    nrf_crypto_ecc_public_key_free(&xpub_b);

    /* ---- Ed25519: keygen, sign, verify ---- */
    TIME_OP(OP_E_KG, "ed25519-kg",
            nrf_crypto_ecc_key_pair_generate(
              NULL, &g_nrf_crypto_ecc_ed25519_curve_info, &epriv, &epub));

    eslen = ED25519_SIG;
    TIME_OP(OP_E_SIGN, "ed25519-sg",
            nrf_crypto_eddsa_sign(NULL, &epriv, emsg, sizeof(emsg),
                                  esig, &eslen));
    TIME_OP(OP_E_VERIFY, "ed25519-vf",
            nrf_crypto_eddsa_verify(NULL, &epub, emsg, sizeof(emsg),
                                    esig, eslen));

    nrf_crypto_ecc_private_key_free(&epriv);
    nrf_crypto_ecc_public_key_free(&epub);

    PROG_TICK(i);
  }

  ecc_session_end();

  /* --- aggregate summary (same format as ecc-bench) --- */
  printf("\n=== SUMMARY (X25519 + Ed25519, %s, %d iters) ===\n",
         ECC_BENCH_BACKEND, BENCH_ITERS);
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
    var = (sumsq - sum * sum / n_samp) / n_samp;   /* population variance */
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
