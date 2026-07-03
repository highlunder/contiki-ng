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
  uint32_t n;          /* completed samples */
  uint32_t fail;       /* failed/aborted operations (not counted in stats) */
  double   mean_us;    /* Welford running mean */
  double   m2_us;      /* Welford running sum of squared deviations */
  uint32_t min_us;
  uint32_t max_us;
  uint32_t last_us;
  uint32_t retx_last;  /* re-attempts of the last operation */
  uint32_t retx_total; /* cumulative re-attempts over all completed operations */
} bench_stats_t;

static inline void
bench_stats_init(bench_stats_t *s)
{
  s->n = 0; s->fail = 0;
  s->mean_us = 0.0; s->m2_us = 0.0;
  s->min_us = 0; s->max_us = 0; s->last_us = 0;
  s->retx_last = 0; s->retx_total = 0;
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
  printf("[BENCH %s] n=%lu fail=%lu last=%lu.%03lu mean=%lu.%03lu "
         "sd=%lu.%03lu min=%lu.%03lu max=%lu.%03lu hops=%d "
         "retx_last=%lu retx_tot=%lu dbg=%d (ms)\n",
         label,
         (unsigned long)s->n, (unsigned long)s->fail,
         BENCH_MS_INT(s->last_us), BENCH_MS_FRAC(s->last_us),
         BENCH_MS_INT(mean),       BENCH_MS_FRAC(mean),
         BENCH_MS_INT(sd),         BENCH_MS_FRAC(sd),
         BENCH_MS_INT(s->min_us),  BENCH_MS_FRAC(s->min_us),
         BENCH_MS_INT(s->max_us),  BENCH_MS_FRAC(s->max_us),
         hops,
         (unsigned long)s->retx_last, (unsigned long)s->retx_total, dbg);
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
  printf("[BENCH %s FINAL] n=%lu fail=%lu mean=%lu.%03lu median=%lu.%03lu "
         "p95=%lu.%03lu sd=%lu.%03lu min=%lu.%03lu max=%lu.%03lu hops=%d "
         "retx_tot=%lu dbg=%d (ms)\n",
         label, (unsigned long)s->n, (unsigned long)s->fail,
         BENCH_MS_INT(mean),      BENCH_MS_FRAC(mean),
         BENCH_MS_INT(median),    BENCH_MS_FRAC(median),
         BENCH_MS_INT(p95),       BENCH_MS_FRAC(p95),
         BENCH_MS_INT(sd),        BENCH_MS_FRAC(sd),
         BENCH_MS_INT(s->min_us), BENCH_MS_FRAC(s->min_us),
         BENCH_MS_INT(s->max_us), BENCH_MS_FRAC(s->max_us),
         hops, (unsigned long)s->retx_total, dbg);
}

/* Radio hops to the RPL root (DAG depth - 1); -1 if not in a DAG. Uses RPL-lite
 * curr_instance; RPL runs over both CSMA and TSCH. */
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

#endif /* BENCH_STATS_H_ */
