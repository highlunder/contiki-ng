/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * nRF52840-DK micro-benchmark: ML-KEM (FIPS 203, a.k.a. Kyber) key
 * establishment -- keygen / encapsulate / decapsulate -- using the vendored
 * pq-crystals REFERENCE implementation (portable C, software only).  Companion
 * to ecc-bench / ec25519-bench, with the SAME DWT cycle-counter + summary
 * harness so classical vs post-quantum are directly comparable.
 *
 * There is no CC310 column: CryptoCell-310 has no lattice/Keccak acceleration,
 * so PQC runs entirely in software.  This reference build is also NOT
 * Cortex-M-optimized (the optimized path is pqm4 / mlkem-native, in ARM asm).
 * The point of the comparison is the system trade-off, not peak speed: on
 * Cortex-M4 the ML-KEM *compute* is modest, but the public key + ciphertext
 * are ~0.8-1.6 KB (vs 32-64 B for ECC) -- which is the cost that lands on the
 * 802.15.4 radio (6LoWPAN fragmentation, airtime, energy) and is exactly where
 * C509 compact certificates + EDHOC message sizing matter.  See the printed
 * "sizes:" line.
 *
 * Build (security level via MLKEM=512|768|1024, default 768):
 *   make TARGET=nrf52840 BOARD=dk MLKEM=768
 *
 * A green LED + "RESULT: PASS" means every op returned 0 and the encapsulated
 * shared secret equals the decapsulated one for all iterations.
 */

#include "contiki.h"
#include "dev/watchdog.h"
#include "dev/leds.h"
#include "mlkem/params.h"
#include "mlkem/kem.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#if KYBER_K == 2
#define MLKEM_NAME "ML-KEM-512"
#elif KYBER_K == 3
#define MLKEM_NAME "ML-KEM-768"
#elif KYBER_K == 4
#define MLKEM_NAME "ML-KEM-1024"
#else
#define MLKEM_NAME "ML-KEM-?"
#endif

#define CPU_HZ        64000000UL
#ifndef BENCH_ITERS
#define BENCH_ITERS   100          /* override from Makefile: ITERS=<n> */
#endif

#ifndef ECC_BENCH_DEBUG
#define ECC_BENCH_DEBUG 0
#endif

#if ECC_BENCH_DEBUG
#define DBG_BEFORE(lbl)        printf("[i=%d] %-7s start...\n", i, (lbl))
#define DBG_AFTER(lbl, c, r)   printf("[i=%d] %-7s done res=%d %lu cyc\n", \
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

/* --- self-contained ARM Cortex-M DWT cycle counter --- */
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

enum { OP_KEYGEN, OP_ENCAPS, OP_DECAPS, N_OPS };
static const char *const op_labels[N_OPS] = { "keygen", "encaps", "decaps" };

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

PROCESS(mlkem_bench_process, "ML-KEM benchmark");
AUTOSTART_PROCESSES(&mlkem_bench_process);

PROCESS_THREAD(mlkem_bench_process, ev, data)
{
  static struct etimer et;
  static uint8_t pk[KYBER_PUBLICKEYBYTES];
  static uint8_t sk[KYBER_SECRETKEYBYTES];
  static uint8_t ct[KYBER_CIPHERTEXTBYTES];
  static uint8_t ss_e[KYBER_SSBYTES], ss_d[KYBER_SSBYTES];
  static uint32_t t, cyc;
  static int i, rc;
  static bool ok = true;
  static bool ss_match[BENCH_ITERS];
  static uint32_t cyc_log[BENCH_ITERS][N_OPS];
  static int res_log[BENCH_ITERS][N_OPS];
  /* summary accumulators */
  static unsigned g, n_samp, fails;
  static uint32_t c, mn, mx, mean_cyc, sd_cyc;
  static uint64_t sum, sumsq, var;

  PROCESS_BEGIN();

  etimer_set(&et, CLOCK_SECOND * 2);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  printf("\n=== nRF52840 ML-KEM benchmark (%s, software ref) ===\n", MLKEM_NAME);
  printf("sizes: pk=%d  sk=%d  ct=%d  ss=%d  (bytes on the wire: pk+ct=%d)\n",
         KYBER_PUBLICKEYBYTES, KYBER_SECRETKEYBYTES, KYBER_CIPHERTEXTBYTES,
         KYBER_SSBYTES, KYBER_PUBLICKEYBYTES + KYBER_CIPHERTEXTBYTES);

  dwt_init();
  t = dwt_now();
  clock_delay_usec(1000);
  cyc = dwt_now() - t;
  printf("DWT sanity: 1 ms delay measured %lu cyc (expect ~%lu)\n",
         (unsigned long)cyc, (unsigned long)(CPU_HZ / 1000UL));

  for(i = 0; i < BENCH_ITERS; i++) {
    TIME_OP(OP_KEYGEN, "keygen", crypto_kem_keypair(pk, sk));
    TIME_OP(OP_ENCAPS, "encaps", crypto_kem_enc(ct, ss_e, pk));
    TIME_OP(OP_DECAPS, "decaps", crypto_kem_dec(ss_d, ct, sk));

    ss_match[i] = (memcmp(ss_e, ss_d, KYBER_SSBYTES) == 0);
    if(!ss_match[i]) {
      ok = false;
    }
    PROG_TICK(i);
  }

  printf("\n=== SUMMARY (%s, software ref, %d iters) ===\n",
         MLKEM_NAME, BENCH_ITERS);
  printf("op        n  nfail   min_us   mean_us    max_us    sd_us\n");
  for(g = 0; g < N_OPS; g++) {
    sum = 0;
    sumsq = 0;
    mn = 0xFFFFFFFFUL;
    mx = 0;
    n_samp = 0;
    fails = 0;
    for(i = 0; i < BENCH_ITERS; i++) {
      c = cyc_log[i][g];
      sum += c;
      sumsq += (uint64_t)c * c;
      if(c < mn) {
        mn = c;
      }
      if(c > mx) {
        mx = c;
      }
      if(res_log[i][g] != 0) {
        fails++;
      }
      n_samp++;
    }
    mean_cyc = (uint32_t)(sum / n_samp);
    var = (sumsq - sum * sum / n_samp) / n_samp;
    sd_cyc = isqrt64(var);
    printf("%-8s %3u  %5u  %8lu  %8lu  %8lu  %8lu\n",
           op_labels[g], n_samp, fails,
           (unsigned long)(mn / (CPU_HZ / 1000000UL)),
           (unsigned long)(mean_cyc / (CPU_HZ / 1000000UL)),
           (unsigned long)(mx / (CPU_HZ / 1000000UL)),
           (unsigned long)(sd_cyc / (CPU_HZ / 1000000UL)));
  }

  printf("\n=== RESULT: %s (%s software ref) ===\n",
         ok ? "PASS" : "FAIL", MLKEM_NAME);
  leds_on(ok ? LEDS_GREEN : LEDS_RED);

  PROCESS_END();
}
