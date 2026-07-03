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
  uint32_t n;         /* completed samples */
  uint32_t fail;      /* failed/aborted operations (not counted in stats) */
  double   mean_us;   /* Welford running mean */
  double   m2_us;     /* Welford running sum of squared deviations */
  uint32_t min_us;
  uint32_t max_us;
  uint32_t last_us;
} bench_stats_t;

static inline void
bench_stats_init(bench_stats_t *s)
{
  s->n = 0; s->fail = 0;
  s->mean_us = 0.0; s->m2_us = 0.0;
  s->min_us = 0; s->max_us = 0; s->last_us = 0;
}

/* Record one successful operation of duration x_us. */
static inline void
bench_stats_add_us(bench_stats_t *s, uint32_t x_us)
{
  double d, d2;
  s->last_us = x_us;
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
 *   [BENCH <label>] n=<ok> fail=<x> last=<ms> mean=<ms> sd=<ms> min=<ms> max=<ms> (ms)
 */
static inline void
bench_stats_print(const char *label, const bench_stats_t *s)
{
  uint32_t sd = bench_stats_stddev_us(s);
  uint32_t mean = (uint32_t)(s->mean_us + 0.5);
  printf("[BENCH %s] n=%lu fail=%lu last=%lu.%03lu mean=%lu.%03lu "
         "sd=%lu.%03lu min=%lu.%03lu max=%lu.%03lu (ms)\n",
         label,
         (unsigned long)s->n, (unsigned long)s->fail,
         BENCH_MS_INT(s->last_us), BENCH_MS_FRAC(s->last_us),
         BENCH_MS_INT(mean),       BENCH_MS_FRAC(mean),
         BENCH_MS_INT(sd),         BENCH_MS_FRAC(sd),
         BENCH_MS_INT(s->min_us),  BENCH_MS_FRAC(s->min_us),
         BENCH_MS_INT(s->max_us),  BENCH_MS_FRAC(s->max_us));
}

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
#define BENCH_ITERS 30          /* default repetitions; override with -DBENCH_ITERS= */
#endif

#endif /* BENCH_STATS_H_ */
