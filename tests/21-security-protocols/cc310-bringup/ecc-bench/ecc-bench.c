/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * nRF52840-DK bring-up rungs 3-5: ECC micro-benchmark (secp256r1).
 *
 * Single-node, no network.  Drives lib/ecc.h directly and reports, per
 * operation, the ARM DWT cycle count and derived time.  The SAME binary logic
 * runs on either backend:
 *   - software (uECC)         : default build
 *   - CC310 hardware          : build with ECC_HW_BACKEND=cc310
 * so the two runs are directly comparable.
 *
 * What it checks:
 *   rung 3  DWT cycle counter is alive (times a known 1 ms delay).
 *   rung 4  ECC works and is CORRECT: keygen -> sign -> verify must pass,
 *           and ECDH(a,B) must equal ECDH(b,A).
 *   rung 5  per-op cost: keygen / sign / verify / ECDH cycles + us + ms.
 *
 * A green LED + "RESULT: PASS" line means the backend is healthy.
 */

#include "contiki.h"
#include "dev/watchdog.h"
#include "dev/leds.h"
#include "lib/ecc.h"
#include "lib/ecc-curve.h"
#include "sys/process-mutex.h"
#include "sys/pt.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#ifndef ECC_BENCH_BACKEND
#define ECC_BENCH_BACKEND "software (uECC)"
#endif

/* Firmware build stamp for record-keeping. FW_BUILD_ID is a short date id the
 * Makefile injects (-DFW_BUILD_ID, default below); printed alongside the
 * compiler's own __DATE__/__TIME__ so any pasted result log is self-identifying
 * (which source/firmware revision produced it). */
#ifndef FW_BUILD_ID
#define FW_BUILD_ID "dev"
#endif

#define CPU_HZ        64000000UL   /* nRF52840 core clock */
#ifndef BENCH_ITERS
#define BENCH_ITERS   100          /* override from Makefile: ITERS=<n> */
#endif
#define KEYLEN        32           /* |secp256r1| */

/* 1 = also dump every per-iteration line (700 lines); 0 = summary table only.
 * Default off: the aggregate SUMMARY block is all the paper tables need and is
 * trivial to paste back. */
#ifndef ECC_BENCH_VERBOSE
#define ECC_BENCH_VERBOSE 0
#endif

/* 1 = print a LIVE trace of every op as it runs (start marker before the op,
 * result after).  Lets you see progress / pinpoint a hang on a slow backend.
 * The prints sit OUTSIDE the timed window (before dwt_now start / after stop)
 * and UART TX is blocking, so the recorded cycle counts stay clean even with
 * debug on -- but expect a lot of output.  Build with ECC_BENCH_DEBUG=1. */
#ifndef ECC_BENCH_DEBUG
#define ECC_BENCH_DEBUG 0
#endif

#if ECC_BENCH_DEBUG
#define DBG_BEFORE(lbl)        printf("[i=%d] %-9s start...\n", i, (lbl))
#define DBG_AFTER(lbl, c, r)   printf("[i=%d] %-9s done res=%d %lu cyc\n", \
                                      i, (lbl), (r), (unsigned long)(c))
#define DBG_ACQFAIL(lbl)       printf("[i=%d] %-9s ACQUIRE FAILED " \
                                      "(ecc_enable rejected curve?)\n", i, (lbl))
/* Full trace already shows progress -- no dots needed. */
#define PROG_DOT()
#define PROG_TICK(n)
#else
#define DBG_BEFORE(lbl)
#define DBG_AFTER(lbl, c, r)
#define DBG_ACQFAIL(lbl)
/* Non-intrusive progress: one dot per op + a counter every 10 iterations.
 * Printed BETWEEN ops (outside the timed window) and UART TX is blocking, so
 * the recorded cycle counts are unaffected -- it just shows the run is alive,
 * which matters for the very slow brainpool path (~10 s/op). */
#define PROG_DOT()             putchar('.')
#define PROG_TICK(n)           do {                                       \
                                 if(((n) + 1) % 10 == 0) {                \
                                   printf(" %d/%d\n", (n) + 1, BENCH_ITERS); \
                                 }                                        \
                               } while(0)
#endif

/* --- self-contained ARM Cortex-M DWT cycle counter (raw regs, no CMSIS) --- */
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004UL)
#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000UL)
#define DEMCR      (*(volatile uint32_t *)0xE000EDFCUL)

static inline void
dwt_init(void)
{
  DEMCR |= (1UL << 24);   /* TRCENA: enable trace/debug subsystem */
  DWT_CYCCNT = 0;
  DWT_CTRL |= 1UL;        /* CYCCNTENA: enable the cycle counter */
}
static inline uint32_t
dwt_now(void)
{
  return DWT_CYCCNT;
}

/* nRF52840 NVMC instruction cache config (base 0x4001E000 + 0x540), CACHEEN=bit0.
 * Contiki's nRF startup leaves the I-cache DISABLED, so flash-resident hot loops
 * (uECC) pay flash wait-states (~2x). Enable it so the per-op cost is realistic
 * and comparable to published M4 numbers; done identically in p256m-bench so the
 * software/p256-m/CC310 rows share one memory system. (CC310 does its math in the
 * CryptoCell engine, so it is largely insensitive to this -- which is exactly why
 * the hw-vs-sw gap must be measured with the cache ON to be fair.) */
#define NVMC_ICACHECNF (*(volatile uint32_t *)0x4001E540UL)

static inline void
icache_enable(void)
{
  NVMC_ICACHECNF = 1UL;   /* CACHEEN = Enabled, profiling off */
}

/*
 * Curve under test, selectable at build time via ECC_BENCH_CURVE:
 *   (default)        secp256r1 / NIST P-256
 *   ECC_BENCH_BP256  brainpoolP256r1 (software backend only -- the CC310
 *                    backend's map_curve() returns NULL for it)
 * lib/ecc-curve.h provides both. Same KEYLEN (32) for both 256-bit curves.
 */
#if defined(ECC_BENCH_BP256)
static const ecc_curve_t *const CURVE = &ecc_curve_brainpool_p_256;
#define ECC_BENCH_CURVE_NAME "brainpoolP256r1"
#else
static const ecc_curve_t *const CURVE = &ecc_curve_p_256;
#define ECC_BENCH_CURVE_NAME "secp256r1"
#endif

/* Mirror EDHOC's acquire_ecc(): lock the mutex, then enable the curve.
 * ecc_enable() unlocks the mutex itself on failure. */
static bool
ecc_acquire(void)
{
  if(!process_mutex_try_lock(ecc_get_mutex())) {
    return false;
  }
  return ecc_enable(CURVE) == 0;
}

#if ECC_BENCH_VERBOSE
static void
report(const char *label, uint32_t cyc, int res)
{
  printf("  %-10s %10lu cyc = %5lu ms (%8lu us)  res=%d\n",
         label, (unsigned long)cyc,
         (unsigned long)(cyc / (CPU_HZ / 1000UL)),
         (unsigned long)(cyc / (CPU_HZ / 1000000UL)), res);
}
#endif

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

/*
 * Per-op operation indices + labels.  Timing results are buffered into
 * cyc_log/res_log during the run and printed ONLY after the whole benchmark
 * finishes (after ecc_session_end()).  This guarantees no UART traffic is ever
 * emitted between a dwt_now() start and stop: the timed region contains
 * nothing but the ECC protothread and watchdog_periodic().
 */
enum {
  OP_KEYGEN_A, OP_KEYGEN_B, OP_SIGN, OP_VERIFY, OP_ECDH_AB, OP_ECDH_BA, N_OPS
};
#if ECC_BENCH_VERBOSE
static const char *const op_labels[N_OPS] = {
  "keygen-A", "keygen-B", "sign", "verify", "ecdh-aB", "ecdh-bA"
};
#endif
#define ACQUIRE_FAILED (-999)

/* Logical primitives for the summary table.  keygen-A/B and ecdh-aB/bA are the
 * same operation run on the two key pairs, so they are pooled (nop==2). */
struct op_group {
  const char *name;
  uint8_t op0;
  uint8_t op1;
  uint8_t nop;
};
static const struct op_group op_groups[] = {
  { "keygen", OP_KEYGEN_A, OP_KEYGEN_B, 2 },
  { "sign",   OP_SIGN,     OP_SIGN,     1 },
  { "verify", OP_VERIFY,   OP_VERIFY,   1 },
  { "ecdh",   OP_ECDH_AB,  OP_ECDH_BA,  2 },
};
#define N_GROUPS (sizeof(op_groups) / sizeof(op_groups[0]))

/* Run one lib/ecc.h protothread op to completion, timing it.  Nothing prints
 * INSIDE the timed window (dwt_now start..stop); the result lands in
 * cyc_log[i][slot]/res_log[i][slot] and any trace/progress output happens
 * before the start marker or after the stop, where it cannot perturb the count. */
#define RUN_OP(slot, label, call)                            \
  do {                                                       \
    if(ecc_acquire()) {                                      \
      DBG_BEFORE(label);                                     \
      t = dwt_now();                                         \
      PT_INIT(ecc_get_protothread());                        \
      while(PT_SCHEDULE(call)) {                             \
        watchdog_periodic();                                 \
      }                                                      \
      cyc = dwt_now() - t;                                   \
      ecc_disable();                                         \
      cyc_log[i][slot] = cyc;                                \
      res_log[i][slot] = res;                                \
      DBG_AFTER(label, cyc, res);                            \
      if(res != 0) {                                         \
        ok = false;                                          \
      }                                                      \
    } else {                                                 \
      cyc_log[i][slot] = 0;                                  \
      res_log[i][slot] = ACQUIRE_FAILED;                     \
      ok = false;                                            \
      DBG_ACQFAIL(label);                                    \
    }                                                        \
    watchdog_periodic();                                     \
    PROG_DOT();                                              \
  } while(0)

PROCESS(ecc_bench_process, "ECC benchmark");
AUTOSTART_PROCESSES(&ecc_bench_process);

PROCESS_THREAD(ecc_bench_process, ev, data)
{
  static struct etimer et;
  static uint8_t pub_a[2 * KEYLEN], priv_a[KEYLEN];
  static uint8_t pub_b[2 * KEYLEN], priv_b[KEYLEN];
  static uint8_t sig[2 * KEYLEN], hash[KEYLEN];
  static uint8_t sec_a[KEYLEN], sec_b[KEYLEN];
  static uint32_t t, cyc;
  static int res, i;
#if ECC_BENCH_VERBOSE
  static int j;
#endif
  static bool ok = true;
  static uint32_t cyc_log[BENCH_ITERS][N_OPS];
  static int res_log[BENCH_ITERS][N_OPS];
  static bool ecdh_match[BENCH_ITERS];
  /* summary accumulators */
  static unsigned g, k, op, n_samp, fails;
  static uint32_t c, mn, mx, mean_cyc, sd_cyc;
  static uint64_t sum, sumsq, var;

  PROCESS_BEGIN();

  /* Let the console settle before the (blocking) benchmark. */
  etimer_set(&et, CLOCK_SECOND * 2);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  printf("\n=== nRF52840 ECC benchmark (%s) ===\n", ECC_BENCH_CURVE_NAME);
  printf("backend: %s\n", ECC_BENCH_BACKEND);
  printf("fw-build: %s  (compiled %s %s)\n", FW_BUILD_ID, __DATE__, __TIME__);

  icache_enable();
  printf("NVMC I-cache: %s\n", (NVMC_ICACHECNF & 1UL) ? "ENABLED" : "disabled");

  /* rung 3: is the DWT cycle counter alive? */
  dwt_init();
  t = dwt_now();
  clock_delay_usec(1000);
  cyc = dwt_now() - t;
  printf("DWT sanity: 1 ms delay measured %lu cyc (expect ~%lu)\n",
         (unsigned long)cyc, (unsigned long)(CPU_HZ / 1000UL));
  if(cyc < (CPU_HZ / 2000UL) || cyc > (CPU_HZ / 250UL)) {
    printf("WARNING: DWT reading implausible -- cycle counter may be inactive "
           "(returns 0 under emulation).\n");
  }

  ecc_init();   /* nrf_crypto_init(): SaSi_LibInit + backend registration */
  memset(hash, 0xA5, sizeof(hash));

  /*
   * DIAGNOSTIC (bare-bones, 2026-06-18): earlier rounds initialized the
   * radio/UART at boot and then powered them off / stopped them at
   * runtime (NETSTACK_RADIO.off(), uart0_set_input(NULL)) -- both ruled
   * out, but that only tests "off after being on", not "never on at all".
   * This build excludes both at the source: NETSTACK_CONF_RADIO is
   * nullradio_driver and UART0_ENABLED is 0 (project-conf.h), so neither
   * nrf52840-ieee.c's init() nor uart0_init()/serial_line_init() ever run
   * at boot -- no runtime calls needed here anymore, removed.
   */

  /* Hold the backend's power/RNG session across the whole benchmark run,
   * standing in for "a handshake's worth of ops" -- see ecc_session_begin()
   * in nrf52840-cc310-ecc.c for why the CC310 backend needs this. */
  ecc_session_begin();

  /* --- benchmark loop: only progress dots / debug trace print here, and only
   *     between ops -- never inside a dwt_now() start..stop window --- */
  for(i = 0; i < BENCH_ITERS; i++) {
    RUN_OP(OP_KEYGEN_A, "keygen-A", ecc_generate_key_pair(pub_a, priv_a, &res));
    RUN_OP(OP_KEYGEN_B, "keygen-B", ecc_generate_key_pair(pub_b, priv_b, &res));
    RUN_OP(OP_SIGN, "sign", ecc_sign(hash, priv_a, sig, &res));
    RUN_OP(OP_VERIFY, "verify", ecc_verify(sig, hash, pub_a, &res));
    RUN_OP(OP_ECDH_AB, "ecdh-aB", ecc_generate_shared_secret(pub_b, priv_a, sec_a, &res));
    RUN_OP(OP_ECDH_BA, "ecdh-bA", ecc_generate_shared_secret(pub_a, priv_b, sec_b, &res));

    ecdh_match[i] = (memcmp(sec_a, sec_b, KEYLEN) == 0);
    if(!ecdh_match[i]) {
      ok = false;
    }
    PROG_TICK(i);
  }

  ecc_session_end();
  /* --- timed region ends: safe to print buffered results now --- */

#if ECC_BENCH_VERBOSE
  for(i = 0; i < BENCH_ITERS; i++) {
    printf("--- iteration %d/%d ---\n", i + 1, BENCH_ITERS);
    for(j = 0; j < N_OPS; j++) {
      report(op_labels[j], cyc_log[i][j], res_log[i][j]);
    }
    printf("  ECDH %s\n",
           ecdh_match[i] ? "shared secrets match (correctness OK)"
                         : "MISMATCH: shared secrets differ!");
  }
#endif

  /* Aggregate summary (computed from the buffers -- still no timing impact).
   * Pasting just this block is enough for the paper tables. */
  printf("\n=== SUMMARY (%s, %s, %d iters, fw %s) ===\n",
         ECC_BENCH_CURVE_NAME, ECC_BENCH_BACKEND, BENCH_ITERS, FW_BUILD_ID);
  printf("op        n  nfail   min_us   mean_us    max_us    sd_us\n");
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
    /* population variance E[X^2]-E[X]^2; avoid forming sum*sum, which overflows
     * uint64 once cyc ~ 7e7 (e.g. verify with the I-cache off). */
    var = sumsq / n_samp - (uint64_t)mean_cyc * mean_cyc;
    sd_cyc = isqrt64(var);
    printf("%-8s %4u  %5u  %8lu  %8lu  %8lu  %8lu\n",
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
