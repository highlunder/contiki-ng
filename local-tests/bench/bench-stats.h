/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 *
 * Shared benchmark harness for the multi-run paper experiments: time a full
 * operation (handshake / enrollment) repeated N times and keep INCREMENTAL
 * (Welford) running statistics, so the LAST printed line alone is the complete
 * result -- copy it and you have n / mean / sample-stddev / min / max. No state
 * to post-process, no host-side reduction.
 *
 * Durations are held in microseconds (uint32, up to ~71 min) measured with
 * RTIMER (wrap-safe unsigned subtraction; on nRF52840 the counter period is
 * many hours, so operations of seconds never wrap). Printed as ms with 3
 * decimals split into integers, since the embedded printf has no %f.
 */
#ifndef BENCH_STATS_H_
#define BENCH_STATS_H_

#include <stdint.h>
#include <stdio.h>
#include "sys/rtimer.h"

/* --- PPK2 energy-window marker (Exp H4, ENERGY-PPK2-RUNBOOK.md) ------------
 *
 * When built with ENERGY_MARKER_PIN=<n>, drive nRF port-1 pin <n> high across
 * the exact region the RTIMER also times, so the PPK2's logic channel D0 marks
 * the same window the latency measurement uses -- energy and latency then refer
 * to one region by construction. Off by default, so timing-only builds are
 * byte-identical to the ones already logged (no GPIO write in the hot path).
 *
 * Port 1 is chosen because it is entirely unused by the nRF52840-DK firmware
 * (every LED/button/UART pin is on port 0); P1.10 is the runbook default. The
 * DK silkscreens the GPIO name at each header pin, so wire D0 to the pin
 * labelled "P1.<n>". Uses the GPIO HAL (portable, no direct register poke). */
#ifdef ENERGY_MARKER_PIN
#include "dev/gpio-hal.h"
#ifndef ENERGY_MARKER_PORT
#define ENERGY_MARKER_PORT 1
#endif
static inline void
bench_marker_init(void)
{
  gpio_hal_arch_pin_set_output(ENERGY_MARKER_PORT, ENERGY_MARKER_PIN);
  gpio_hal_arch_port_clear_pins(ENERGY_MARKER_PORT,
                                (gpio_hal_pin_mask_t)1 << ENERGY_MARKER_PIN);
}
static inline void
bench_marker_high(void)
{
  gpio_hal_arch_port_set_pins(ENERGY_MARKER_PORT,
                              (gpio_hal_pin_mask_t)1 << ENERGY_MARKER_PIN);
}
static inline void
bench_marker_low(void)
{
  gpio_hal_arch_port_clear_pins(ENERGY_MARKER_PORT,
                                (gpio_hal_pin_mask_t)1 << ENERGY_MARKER_PIN);
}
#else
static inline void bench_marker_init(void) {}
static inline void bench_marker_high(void) {}
static inline void bench_marker_low(void) {}
#endif /* ENERGY_MARKER_PIN */

/* Integer sqrt (bit-by-bit) so the harness needs no libm: the running mean/M2
 * stay in double (basic soft-float, no libm), only the final stddev takes a
 * root, on the integer variance. */
static inline uint64_t
bench_isqrt64(uint64_t x)
{
  uint64_t res = 0;
  uint64_t bit = (uint64_t)1 << 62;
  while(bit > x) { bit >>= 2; }
  while(bit != 0) {
    if(x >= res + bit) { x -= res + bit; res = (res >> 1) + bit; }
    else { res >>= 1; }
    bit >>= 2;
  }
  return res;
}

typedef struct {
  uint32_t n;          /* completed samples (the OPERATION succeeded) */
  uint32_t fail;       /* the OPERATION failed (e.g. handshake never completed) */
  /* Post-operation verification (e.g. the untimed CoAP GET after a DTLS
   * handshake) failed while the operation ITSELF succeeded. Kept separate from
   * `fail` so a lost liveness-check GET does not discard a valid handshake-
   * latency sample -- the handshake is still recorded in n/mean/... */
  uint32_t get_fail;
  double   mean_us;    /* Welford running mean */
  double   m2_us;      /* Welford running sum of squared deviations */
  uint32_t min_us;
  uint32_t max_us;
  uint32_t last_us;
  uint32_t retx_last;  /* re-attempts of the last operation */
  uint32_t retx_total; /* cumulative re-attempts over all completed operations */
  /* RPL DODAG repair, as OBSERVED by the app: how long an iteration had to wait
   * for NETSTACK_ROUTING.node_is_reachable() to come back before it could run.
   * Nonzero only when the route was actually down at iteration start (parent
   * eviction / churn). Poll-granular (the re-wait etimer period, ~1-2 s), so
   * read it as "the node could not proceed for ~this long while RPL healed",
   * not a sub-second RPL-internal figure. A failed op during an outage also
   * self-flags via hops=-1 on its printed line. */
  uint32_t repair_events;   /* iterations that waited through a repair */
  uint32_t repair_us_last;  /* repair wait before the LAST op (0 if route was up) */
  uint32_t repair_us_total; /* cumulative repair wait */
  uint32_t repair_us_max;   /* worst single repair wait */
} bench_stats_t;

static inline void
bench_stats_init(bench_stats_t *s)
{
  s->n = 0; s->fail = 0; s->get_fail = 0;
  s->mean_us = 0.0; s->m2_us = 0.0;
  s->min_us = 0; s->max_us = 0; s->last_us = 0;
  s->retx_last = 0; s->retx_total = 0;
  s->repair_events = 0; s->repair_us_last = 0;
  s->repair_us_total = 0; s->repair_us_max = 0;
}

/* Clear the per-iteration repair figure; call at the top of each iteration
 * before the reachability re-wait so a stale value isn't reprinted. */
static inline void
bench_stats_repair_reset_last(bench_stats_t *s)
{
  s->repair_us_last = 0;
}

/* Record an observed RPL repair wait of `us` microseconds. */
static inline void
bench_stats_add_repair(bench_stats_t *s, uint32_t us)
{
  s->repair_events++;
  s->repair_us_last = us;
  s->repair_us_total += us;
  if(us > s->repair_us_max) { s->repair_us_max = us; }
}

/* Record one successful operation: duration x_us, and `retx` re-attempts /
 * retransmits it took (0 = first-try success). */
static inline void
bench_stats_add_us(bench_stats_t *s, uint32_t x_us, uint32_t retx)
{
  double d, d2;
  s->last_us = x_us;
  s->retx_last = retx;
  s->retx_total += retx;
  s->n++;
  d = (double)x_us - s->mean_us;
  s->mean_us += d / (double)s->n;
  d2 = (double)x_us - s->mean_us;
  s->m2_us += d * d2;
  if(s->n == 1) {
    s->min_us = s->max_us = x_us;
  } else {
    if(x_us < s->min_us) { s->min_us = x_us; }
    if(x_us > s->max_us) { s->max_us = x_us; }
  }
}

static inline void
bench_stats_add_fail(bench_stats_t *s)
{
  s->fail++;
}

/* Record that the post-operation verification (GET) failed though the operation
 * itself succeeded. The operation's latency should still be recorded via
 * bench_stats_add_us() -- this only tracks the liveness-check failure. */
static inline void
bench_stats_add_get_fail(bench_stats_t *s)
{
  s->get_fail++;
}

/* Sample standard deviation (n-1), in microseconds; 0 for n < 2. */
static inline uint32_t
bench_stats_stddev_us(const bench_stats_t *s)
{
  double var;
  if(s->n < 2) {
    return 0;
  }
  var = s->m2_us / (double)(s->n - 1);        /* sample variance, us^2 */
  if(var < 0.0) { var = 0.0; }
  return (uint32_t)bench_isqrt64((uint64_t)(var + 0.5));
}

/* us -> "ms.mmm" for printf, split to avoid %f. */
#define BENCH_MS_INT(us)  ((unsigned long)((us) / 1000u))
#define BENCH_MS_FRAC(us) ((unsigned long)((us) % 1000u))

/* Firmware build stamp for record-keeping. FW_BUILD_ID is a short date id the
 * Makefile injects (-DFW_BUILD_ID, default below); __DATE__/__TIME__ are the
 * compile time. Print it BOTH at startup and again with the FINAL line so a
 * pasted result block is self-identifying (which firmware produced it) without
 * scrolling back. `backend` (optional) names the crypto path, e.g. the EDHOC
 * ECC backend; pass NULL where it does not apply (DTLS PSK/cert via mbedTLS). */
#ifndef FW_BUILD_ID
#define FW_BUILD_ID "dev"
#endif
static inline void
bench_print_fw_build(const char *backend)
{
  if(backend != NULL && backend[0] != '\0') {
    printf("fw-build: %s  (compiled %s %s)  ecc-backend: %s\n",
           FW_BUILD_ID, __DATE__, __TIME__, backend);
  } else {
    printf("fw-build: %s  (compiled %s %s)\n",
           FW_BUILD_ID, __DATE__, __TIME__);
  }
}

/*
 * Print ONE self-contained cumulative-statistics line. `label` identifies the
 * experiment + configuration (e.g. "edhoc-c5t-cc310-csma"). Copy the last such
 * line for the run's statistics. Format is stable and grep/awk-friendly:
 *
 *   [BENCH <label>] n=<ok> fail=<x> last/mean/sd/min/max=<ms> hops=<h> \
 *       retx_last=<r> retx_tot=<R> dbg=<0|1> (ms)
 *
 * `hops` = radio hops to the RPL root (for multi-hop re-use); `dbg` flags
 * whether verbose logging was compiled in (which inflates timing) so the line
 * is never silently mis-read.
 */
static inline void
bench_stats_print(const char *label, const bench_stats_t *s, int hops, int dbg)
{
  uint32_t sd = bench_stats_stddev_us(s);
  uint32_t mean = (uint32_t)(s->mean_us + 0.5);
  printf("[BENCH %s] n=%lu fail=%lu get_fail=%lu last=%lu.%03lu mean=%lu.%03lu "
         "sd=%lu.%03lu min=%lu.%03lu max=%lu.%03lu hops=%d "
         "retx_last=%lu retx_tot=%lu rpl_rep_ms=%lu.%03lu dbg=%d (ms)\n",
         label,
         (unsigned long)s->n, (unsigned long)s->fail, (unsigned long)s->get_fail,
         BENCH_MS_INT(s->last_us), BENCH_MS_FRAC(s->last_us),
         BENCH_MS_INT(mean),       BENCH_MS_FRAC(mean),
         BENCH_MS_INT(sd),         BENCH_MS_FRAC(sd),
         BENCH_MS_INT(s->min_us),  BENCH_MS_FRAC(s->min_us),
         BENCH_MS_INT(s->max_us),  BENCH_MS_FRAC(s->max_us),
         hops,
         (unsigned long)s->retx_last, (unsigned long)s->retx_total,
         BENCH_MS_INT(s->repair_us_last), BENCH_MS_FRAC(s->repair_us_last),
         dbg);
}

/* In-place ascending sort (insertion; n<=BENCH_ITERS, done once at the end, so
 * no libc qsort dependency). */
static inline void
bench_sort_u32(uint32_t *a, uint32_t n)
{
  uint32_t i, j, v;
  for(i = 1; i < n; i++) {
    v = a[i]; j = i;
    while(j > 0 && a[j - 1] > v) { a[j] = a[j - 1]; j--; }
    a[j] = v;
  }
}

/* Nearest-rank percentile (pct 0..100) on a sorted array. */
static inline uint32_t
bench_percentile_us(const uint32_t *sorted, uint32_t n, uint32_t pct)
{
  if(n == 0) { return 0; }
  return sorted[(uint32_t)(((uint64_t)pct * (n - 1)) / 100)];
}

/*
 * Final summary line with ROBUST stats (median + p95) alongside mean/sd, for the
 * right-skewed handshake-latency data where a few slow tails make mean/sd
 * outlier-sensitive. `samples` holds the first s->n successful durations (us);
 * this sorts it in place. Call once after the loop; copy this line as the result.
 *
 *   [BENCH <label> FINAL] n= fail= mean= median= p95= sd= min= max= hops= \
 *       retx_tot= dbg= (ms)
 */
static inline void
bench_stats_print_final(const char *label, const bench_stats_t *s,
                        uint32_t *samples, int hops, int dbg)
{
  uint32_t sd = bench_stats_stddev_us(s);
  uint32_t mean = (uint32_t)(s->mean_us + 0.5);
  uint32_t median = 0, p95 = 0;
  if(s->n > 0) {
    bench_sort_u32(samples, s->n);
    median = (s->n & 1u) ? samples[s->n / 2]
                         : (samples[s->n / 2 - 1] + samples[s->n / 2]) / 2;
    p95 = bench_percentile_us(samples, s->n, 95);
  }
  printf("[BENCH %s FINAL] n=%lu fail=%lu get_fail=%lu mean=%lu.%03lu median=%lu.%03lu "
         "p95=%lu.%03lu sd=%lu.%03lu min=%lu.%03lu max=%lu.%03lu hops=%d "
         "retx_tot=%lu rpl_rep_events=%lu rpl_rep_ms_tot=%lu.%03lu "
         "rpl_rep_ms_max=%lu.%03lu dbg=%d (ms)\n",
         label, (unsigned long)s->n, (unsigned long)s->fail, (unsigned long)s->get_fail,
         BENCH_MS_INT(mean),      BENCH_MS_FRAC(mean),
         BENCH_MS_INT(median),    BENCH_MS_FRAC(median),
         BENCH_MS_INT(p95),       BENCH_MS_FRAC(p95),
         BENCH_MS_INT(sd),        BENCH_MS_FRAC(sd),
         BENCH_MS_INT(s->min_us), BENCH_MS_FRAC(s->min_us),
         BENCH_MS_INT(s->max_us), BENCH_MS_FRAC(s->max_us),
         hops, (unsigned long)s->retx_total,
         (unsigned long)s->repair_events,
         BENCH_MS_INT(s->repair_us_total), BENCH_MS_FRAC(s->repair_us_total),
         BENCH_MS_INT(s->repair_us_max),   BENCH_MS_FRAC(s->repair_us_max),
         dbg);
}

/*
 * Integer-only variant of bench_stats_print_final: computes mean / median / p95 /
 * sd / min / max entirely from the `samples` array (first `n` successful durations,
 * us) with uint64 arithmetic and the integer sqrt -- NO doubles. Same line format
 * (and same label/hops/dbg semantics) as bench_stats_print_final, so it is a
 * drop-in for it. Prefer this where the platform's soft-float `double` path is
 * unreliable (e.g. the cooja-ng nRF emulator mis-emulates __aeabi_ddiv for some
 * operands, yielding a bogus Welford mean while the integer min/max/median stay
 * correct); the exact integer reduction is safe on both the emulator and real HW.
 * `fail`/`get_fail` are passed through for the printed counters. Sorts `samples`.
 *
 * Overflow envelope: x <= ~4.3e9 us (uint32 max); sum of n<=BENCH_ITERS samples and
 * sum of squared deviations both stay far inside uint64 for realistic n and ms-scale
 * durations.
 */
static inline void
bench_stats_print_final_int(const char *label, uint32_t *samples, uint32_t n,
                            uint32_t fail, uint32_t get_fail, int hops, int dbg)
{
  uint32_t mean = 0, median = 0, p95 = 0, sd = 0, mn = 0, mx = 0;
  if(n > 0) {
    uint64_t sum = 0;
    uint32_t i;
    bench_sort_u32(samples, n);
    for(i = 0; i < n; i++) { sum += samples[i]; }
    mean = (uint32_t)((sum + n / 2) / n);       /* rounded integer mean */
    median = (n & 1u) ? samples[n / 2]
                      : (samples[n / 2 - 1] + samples[n / 2]) / 2;
    p95 = bench_percentile_us(samples, n, 95);
    mn = samples[0];
    mx = samples[n - 1];
    if(n >= 2) {
      uint64_t ss = 0;
      for(i = 0; i < n; i++) {
        int64_t dv = (int64_t)samples[i] - (int64_t)mean;
        ss += (uint64_t)(dv * dv);
      }
      sd = (uint32_t)bench_isqrt64(ss / (n - 1));   /* sample stddev (n-1) */
    }
  }
  printf("[BENCH %s FINAL] n=%lu fail=%lu get_fail=%lu mean=%lu.%03lu median=%lu.%03lu "
         "p95=%lu.%03lu sd=%lu.%03lu min=%lu.%03lu max=%lu.%03lu hops=%d dbg=%d (ms)\n",
         label, (unsigned long)n, (unsigned long)fail, (unsigned long)get_fail,
         BENCH_MS_INT(mean),   BENCH_MS_FRAC(mean),
         BENCH_MS_INT(median), BENCH_MS_FRAC(median),
         BENCH_MS_INT(p95),    BENCH_MS_FRAC(p95),
         BENCH_MS_INT(sd),     BENCH_MS_FRAC(sd),
         BENCH_MS_INT(mn),     BENCH_MS_FRAC(mn),
         BENCH_MS_INT(mx),     BENCH_MS_FRAC(mx),
         hops, dbg);
}

/* Approximate radio hops to the RPL root, as DAG_RANK(rank) - 1; -1 if not in a
 * DAG. Uses RPL-lite curr_instance; RPL runs over both CSMA and TSCH.
 *
 * CAVEAT (important when reading results): this is derived from the RPL *rank*,
 * which is ETX-weighted (rank = parent_rank + link_metric), NOT a topological
 * hop count. On a congested single-hop link -- e.g. the cert-DTLS benches, which
 * flood the radio with ~22 6LoWPAN fragments per handshake -- the link ETX
 * inflates, the rank climbs (RPL_MIN_HOPRANKINC is 128 for MRHOF, so a healthy
 * 1-hop child is rank ~256 => hops 1), and this can report "hops" of 5-10 while
 * the node is still one physical hop from the same parent. So a rising `hops`
 * in a known single-hop testbed is a LINK-STRESS signal, not extra depth. */
#include "net/routing/routing.h"
#if ROUTING_CONF_RPL_LITE
#include "net/routing/rpl-lite/rpl.h"
static inline int
bench_rpl_hops(void)
{
  if(!curr_instance.used || curr_instance.dag.rank == RPL_INFINITE_RANK) {
    return -1;
  }
  return (int)DAG_RANK(curr_instance.dag.rank) - 1;
}
#else
static inline int bench_rpl_hops(void) { return -1; }
#endif

/* --- timing --- */
static inline rtimer_clock_t
bench_time_now(void)
{
  return RTIMER_NOW();
}

/* Elapsed microseconds between two RTIMER samples (unsigned wrap-safe). */
static inline uint32_t
bench_elapsed_us(rtimer_clock_t start, rtimer_clock_t end)
{
  rtimer_clock_t d = end - start;
  return (uint32_t)(((uint64_t)d * 1000000u) / RTIMER_SECOND);
}

#ifndef BENCH_ITERS
#define BENCH_ITERS 100         /* default repetitions; override with -DBENCH_ITERS= */
#endif

/* Robustness knobs so a long run recovers from failures instead of stalling:
 *  - HS_DEADLINE: per-iteration hard cap; abort a stuck operation (below the
 *    protocol's own internal retry budget so one bad iteration can't hang ~40 s).
 *  - FAIL_SETTLE: longer inter-iteration pause after a failure, to let RPL/ETX
 *    heal (rapid back-to-back handshakes inflate rank and degrade the route).
 * The loop also re-waits for node_is_reachable() before each iteration. */
#ifndef BENCH_HS_DEADLINE_S
#define BENCH_HS_DEADLINE_S 15
#endif
#ifndef BENCH_FAIL_SETTLE_S
#define BENCH_FAIL_SETTLE_S 15
#endif

/* DTLS handshake completion is detected by polling coap_endpoint_is_connected()
 * (unlike EDHOC, which finishes on an event). Poll this often: t1 is captured up
 * to one poll-interval after the true completion, so the poll period is the
 * timing resolution. 100 ms replaces the old 1 s poll that quantized every DTLS
 * handshake to ~1000 ms. The deadline is a separate etimer, so a fine poll does
 * not shorten it. */
#ifndef BENCH_HS_POLL_MS
#define BENCH_HS_POLL_MS 100
#endif
/* ms -> clock ticks, at least 1 (CLOCK_SECOND varies by target: 128 on nRF). */
#define BENCH_HS_POLL_TICKS                                              \
  (((CLOCK_SECOND) * (BENCH_HS_POLL_MS) / 1000) > 0                      \
   ? ((CLOCK_SECOND) * (BENCH_HS_POLL_MS) / 1000) : 1)

#endif /* BENCH_STATS_H_ */
