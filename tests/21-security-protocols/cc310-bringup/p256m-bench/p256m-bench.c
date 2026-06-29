/*
 * P-256 micro-benchmark using p256-m (modern, compact, constant-time software
 * P-256). The third column for the enrollment crypto comparison:
 *   - software (uECC)    : ecc-bench (default)
 *   - CC310 hardware     : ecc-bench ECC_HW_BACKEND=cc310
 *   - software (p256-m)  : THIS app
 *
 * Same DWT-cycle timing and SUMMARY format as ecc-bench so the rows line up.
 * Answers: does a modern P-256 sw lib beat CC310, as Monocypher did for Ed25519?
 *
 * Board-targeted (cycle measurement needs real hw; emulated crypto is too slow).
 */
#include "contiki.h"
#include "lib/random.h"
#include "p256-m.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define CPU_HZ      64000000UL          /* nRF52840 core clock */
#ifndef BENCH_ITERS
#define BENCH_ITERS 100
#endif

/* Firmware build stamp for record-keeping. FW_BUILD_ID is a short date id the
 * Makefile injects (-DFW_BUILD_ID, default below); printed with the compiler's
 * own __DATE__/__TIME__ so any pasted result log is self-identifying. */
#ifndef FW_BUILD_ID
#define FW_BUILD_ID "dev"
#endif

/* --- self-contained ARM Cortex-M DWT cycle counter (raw regs, no CMSIS) --- */
#define DWT_CYCCNT (*(volatile uint32_t *)0xE0001004UL)
#define DWT_CTRL   (*(volatile uint32_t *)0xE0001000UL)
#define DEMCR      (*(volatile uint32_t *)0xE000EDFCUL)

/* nRF52840 NVMC instruction cache config (base 0x4001E000 + 0x540), CACHEEN=bit0.
 * Contiki's nRF startup leaves the I-cache DISABLED, so flash-resident hot loops
 * (uECC, p256-m) pay flash wait-states (~2x). Enable it so the per-op cost is the
 * realistic, as-deployed figure and is comparable to published M4 numbers (whose
 * reference boards have zero-wait flash). Done identically in ecc-bench so the
 * software/p256-m/CC310 rows are measured under the same memory system. */
#define NVMC_ICACHECNF (*(volatile uint32_t *)0x4001E540UL)

static void
icache_enable(void)
{
  NVMC_ICACHECNF = 1UL;   /* CACHEEN = Enabled, profiling off */
}

static void
cyc_start(void)
{
  DEMCR |= (1UL << 24);   /* TRCENA */
  DWT_CYCCNT = 0;
  DWT_CTRL |= 1UL;        /* CYCCNTENA */
}
static uint32_t
cyc_read(void)
{
  return DWT_CYCCNT;
}

/* p256-m's required RNG. Benchmark-grade: the per-signature nonce and keygen
 * scalar only need to be valid (in range); p256-m rejects+retries bad draws. */
int
p256_generate_random(uint8_t *output, unsigned output_size)
{
  for(unsigned i = 0; i < output_size; i++) {
    output[i] = (uint8_t)random_rand();
  }
  return 0;
}

static uint64_t
isqrt64(uint64_t v)
{
  uint64_t x = v, y = (x + 1) / 2;
  if(v == 0) {
    return 0;
  }
  while(y < x) {
    x = y;
    y = (x + v / x) / 2;
  }
  return x;
}

enum { OP_KEYGEN, OP_SIGN, OP_VERIFY, OP_ECDH, N_OPS };
static const char *const op_name[N_OPS] = { "keygen", "sign", "verify", "ecdh" };

PROCESS(p256m_bench_process, "p256-m benchmark");
AUTOSTART_PROCESSES(&p256m_bench_process);

PROCESS_THREAD(p256m_bench_process, ev, data)
{
  static uint32_t cyc_log[BENCH_ITERS][N_OPS];
  static int res_log[BENCH_ITERS][N_OPS];
  static unsigned i, op;
  static uint8_t priv_a[32], pub_a[64], priv_b[32], pub_b[64];
  static uint8_t sig[64], hash[32], secret[32];
  static uint32_t t0;

  PROCESS_BEGIN();

  for(i = 0; i < 32; i++) {
    hash[i] = (uint8_t)(i * 7 + 1);
  }

  icache_enable();
  cyc_start();
  printf("\n=== nRF52840 P-256 benchmark (p256-m, %d iters) ===\n", BENCH_ITERS);
  printf("fw-build: %s  (compiled %s %s)\n", FW_BUILD_ID, __DATE__, __TIME__);
  printf("NVMC I-cache: %s\n", (NVMC_ICACHECNF & 1UL) ? "ENABLED" : "disabled");

  /* DWT sanity. */
  t0 = cyc_read();
  clock_delay_usec(1000);
  printf("DWT sanity: 1 ms delay measured %lu cyc (expect ~%lu)\n",
         (unsigned long)(cyc_read() - t0), (unsigned long)(CPU_HZ / 1000UL));

  for(i = 0; i < BENCH_ITERS; i++) {
    t0 = cyc_read();
    res_log[i][OP_KEYGEN] = p256_gen_keypair(priv_a, pub_a);
    cyc_log[i][OP_KEYGEN] = cyc_read() - t0;
    p256_gen_keypair(priv_b, pub_b);   /* peer key for ECDH (untimed) */

    t0 = cyc_read();
    res_log[i][OP_SIGN] = p256_ecdsa_sign(sig, priv_a, hash, sizeof(hash));
    cyc_log[i][OP_SIGN] = cyc_read() - t0;

    t0 = cyc_read();
    res_log[i][OP_VERIFY] = p256_ecdsa_verify(sig, pub_a, hash, sizeof(hash));
    cyc_log[i][OP_VERIFY] = cyc_read() - t0;

    t0 = cyc_read();
    res_log[i][OP_ECDH] = p256_ecdh_shared_secret(secret, priv_a, pub_b);
    cyc_log[i][OP_ECDH] = cyc_read() - t0;

    PROCESS_PAUSE();   /* yield so the watchdog/console keep up */
  }

  printf("\n=== SUMMARY (secp256r1, software (p256-m), %d iters, fw %s) ===\n",
         BENCH_ITERS, FW_BUILD_ID);
  printf("op        n  nfail   min_us   mean_us    max_us    sd_us\n");
  for(op = 0; op < N_OPS; op++) {
    uint64_t sum = 0, sumsq = 0;
    uint32_t mn = 0xFFFFFFFFUL, mx = 0, c;
    unsigned fails = 0;
    for(i = 0; i < BENCH_ITERS; i++) {
      c = cyc_log[i][op];
      sum += c;
      sumsq += (uint64_t)c * c;
      if(c < mn) { mn = c; }
      if(c > mx) { mx = c; }
      if(res_log[i][op] != 0) { fails++; }
    }
    uint32_t mean_cyc = (uint32_t)(sum / BENCH_ITERS);
    /* var = E[X^2] - E[X]^2; compute this way (not (sumsq - sum*sum/N)/N) so we
     * never form sum*sum, which overflows uint64 once cyc ~ 7e7 (verify). */
    uint64_t var = sumsq / BENCH_ITERS - (uint64_t)mean_cyc * mean_cyc;
    uint32_t sd_cyc = (uint32_t)isqrt64(var);
    printf("%-8s %4u  %5u  %8lu  %8lu  %8lu  %8lu\n",
           op_name[op], BENCH_ITERS, fails,
           (unsigned long)(mn / (CPU_HZ / 1000000UL)),
           (unsigned long)(mean_cyc / (CPU_HZ / 1000000UL)),
           (unsigned long)(mx / (CPU_HZ / 1000000UL)),
           (unsigned long)(sd_cyc / (CPU_HZ / 1000000UL)));
  }
  printf("p256-m benchmark complete\n");

  PROCESS_END();
}
