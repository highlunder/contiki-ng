# Multi-run benchmark firmwares (paper experiments)

Timed, **repeated** versions of the paper's operations (handshake / enrollment).
Each firmware runs the full operation `BENCH_ITERS` times, times each with
RTIMER, and prints **one incremental (Welford) statistics line per completed
cycle** — so the **last printed line alone is the complete result**:

```
[BENCH edhoc-c5t-cc310-csma] n=30 fail=0 last=812.443 mean=825.101 sd=38.900 min=780.010 max=910.775 hops=1 retx_last=0 retx_tot=1 dbg=0 (ms)
```

Copy that line and you have the whole result, no host-side reduction. Fields:
- `n` / `fail` — completed / failed operations.
- `last mean sd min max` — this-cycle + running mean / **sample** stddev / min / max (ms).
- `hops` — radio hops to the RPL root (for multi-hop re-use; `-1` if not joined).
- `retx_last` / `retx_tot` — EDHOC handshake re-attempts (restarts) this cycle / cumulative.
- `dbg` — **0 = quiet (timing-accurate); 1 = verbose logging compiled in** (inflates
  timing). Always check this before trusting a number.

The label encodes experiment + ECC backend + MAC. Harness: `bench-stats.h` (no
libm — integer sqrt; durations in µs, printed ms.mmm).

**Copy the FINAL line for the result.** After the last iteration the run prints a
robust summary (median + p95 alongside mean/sd), computed by sorting the stored
successful durations once at the end:
```
[BENCH edhoc-c5t-cc310-csma FINAL] n=100 fail=1 mean=... median=... p95=... sd=... min=... max=... hops=... retx_tot=... dbg=0 (ms)
```
Handshake latency over real RF is right-skewed (slow tails from link retransmit
bursts), so **`median` is the honest central value** and `p95` shows the tail;
`mean`/`sd` are kept but are outlier-sensitive. The per-iteration `[BENCH …]`
lines stay purely incremental (mean/sd/min/max) for live monitoring.

**Quiet by default:** EDHOC trace/info logging is off (LOG levels lowered) so
console I/O doesn't inflate the timed handshake. Build with `BENCH_DEBUG=1` to
restore full logging for diagnosis — the BENCH line then reports `dbg=1`.

These are **separate** from the functional rungs in `../` (those are kept
intact); the bench apps reuse the same client/EDHOC code with a loop wrapper.

## Built

| firmware | operation | ECC | MAC | server |
|---|---|---|---|---|
| `bench-edhoc-c5t-{sw,cc310}-{csma,tsch}.hex` | EDHOC+OSCORE **c5t** handshake (cert hash) | sw / CC310 | CSMA / TSCH | native responder `[fd01::302:304:506:1]` |
| `bench-edhoc-c5c-{sw,cc310}-{csma,tsch}.hex` | EDHOC+OSCORE **c5c** handshake (inline cert) | sw / CC310 | CSMA / TSCH | native responder `[fd01::302:304:506:1]` |
| `bench-dtls-psk-{csma,tsch}.hex` | DTLS handshake + PSK | mbedtls | CSMA / TSCH | setest `[fd00::1]:5686` |
| `bench-dtls-x509-{csma,tsch}.hex` | DTLS handshake + X.509 | mbedtls | CSMA / TSCH | setest `[fd00::1]:5684` |
| `bench-dtls-c509-{csma,tsch}.hex` | DTLS handshake + C509 (Type-2) | mbedtls | CSMA / TSCH | setest `[fd00::1]:5687` |

Build: `./build-bench-rungs.sh`. Iterations default to **100**; override for the
whole build with `BENCH_ITERS=30 ./build-bench-rungs.sh` (or per-app
`-DBENCH_ITERS=`). It's a compile-time constant, so changing it means a rebuild.

## Failure recovery (long runs)
Rapid back-to-back handshakes drive RPL ETX up and inflate the node's rank
(`hops` climbs), which can degrade the route; a naive loop then hangs on a stuck
handshake and never recovers. The loop guards against this:
- **`BENCH_HS_DEADLINE_S`** (15) — hard per-iteration cap; a stuck handshake is
  aborted and recorded as `fail` instead of hanging on the protocol's internal
  retry budget (~40 s).
- **re-wait for `node_is_reachable()`** at the top of each iteration — if the
  route dropped, wait for it to come back before the next attempt.
- **`BENCH_FAIL_SETTLE_S`** (15) — after a failure, settle longer (vs
  `BENCH_SETTLE_S`=3 after a success) to let RPL/ETX heal before hammering again.

So a long run records the occasional `fail` and keeps going rather than stalling.
Watch `hops` and `fail` in the last line: rising `hops` means the link is
degrading under the load — increase `BENCH_SETTLE_S` (slower but gentler) if the
fail rate is high. EDHOC gets the sw/CC310 axis (its ECC
routes through the switchable `os/services/ecc`); DTLS uses mbedtls' own crypto,
so no CC310 axis. DTLS benches target the Python setest at `fd00::1` (which
already loops per connection); EDHOC targets the bridged native responder.
`retx` on DTLS is always 0 (mbedtls flight retransmits aren't exposed);
on EDHOC it's the handshake restart count. Every firmware prints a
`[BENCH] connected: joined DODAG, hops=N ...` line once it joins, before timing.

## Run (EDHOC c5t)
1. Firefly gateway up + EDHOC bridge up: `run-edhoc-gateway.sh D` (see
   `../../../secure-endpoint-test-server/`). The responder **already loops** and
   `edhoc_server_reset_handshake()`s per session — no server change needed.
2. Flash a `bench-edhoc-c5t-*.hex`, reset, and let it run. Each cycle prints a
   `[BENCH …]` line; grab the **last** one. Flash the `sw` then the `cc310`
   variant to get the software-vs-CryptoCell whole-handshake comparison.

## Enabling the re-run (library fixes already in place)
The EDHOC handshake now re-runs cleanly in a loop because of two fixes
(`edhoc-client.c`, committed): `ecc_session_begin()/end()` wrap
`edhoc_client_run()/close()` (needed for CC310, no-op for sw), and the static
`attempt` retry counter is reset in `edhoc_client_init()` (else a 2nd handshake
starts already at the attempt cap).

## TSCH note
The TSCH client firmwares build, but a TSCH run needs the **whole path** on
TSCH: a TSCH Firefly border-router (coordinator, `tsch_set_coordinator(1)`) and a
TSCH-built native responder. The CSMA variants run on the current gateway as-is.
Bringing up the TSCH border-router + responder is the next step (in-emulator TSCH
now works after the cooja-ng merge — see the TSCH-energy plan).

## Crypto-vs-RF split — DONE (`EDHOC_PROFILE`)
`edhoc-profile.h` reports per-op **rtimer µs** (as well as DWT cycles, which are
0 in cooja-ng — no CYCCNT model). `emul/run-emul-profile.sh` builds client +
responder with `-DEDHOC_PROFILE_CYCLES` and times every ECC op on both nodes.
Measured split + the "why the emulator is 1.4× slower" finding (it's the
emulated responder's crypto; the hw responder is a free native x86 server) are
written up in **BENCH-RESULTS-LOG.md**. On hardware, rebuild any EDHOC bench
`make … EDHOC_PROFILE=1` to get the same per-op lines (DWT cycles are real
there).

## TODO — remaining experiments
Same harness + loop pattern:
- `bench-edhoc-x509` (EDHOC + X.509 x5chain, scenario C).
- `bench-enroll` — full EDHOC+OSCORE /crts+/sen CSR enrollment cycle.
- Stand up the TSCH border-router + responder so the `-tsch` firmwares have a
  network (they build, but need the whole path on TSCH).
- A results log (paste the last `[BENCH]` line per config).

SECURITY NOTICE: Test credentials only. Never use in production.
