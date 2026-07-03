# Multi-run benchmark firmwares (paper experiments)

Timed, **repeated** versions of the paper's operations (handshake / enrollment).
Each firmware runs the full operation `BENCH_ITERS` times, times each with
RTIMER, and prints **one incremental (Welford) statistics line per completed
cycle** — so the **last printed line alone is the complete result**:

```
[BENCH edhoc-c5t-cc310-csma] n=30 fail=0 last=812.443 mean=825.101 sd=38.900 min=780.010 max=910.775 (ms)
```

Copy that line and you have `n / mean / sample-stddev / min / max` (ms), no
host-side reduction. The label encodes experiment + ECC backend + MAC, so a
pasted line is self-identifying. Harness: `bench-stats.h` (no libm — integer
sqrt; durations in µs, printed ms.mmm).

These are **separate** from the functional rungs in `../` (those are kept
intact); the bench apps reuse the same client/EDHOC code with a loop wrapper.

## Built

| firmware | operation | ECC | MAC | server |
|---|---|---|---|---|
| `bench-edhoc-c5t-{sw,cc310}-{csma,tsch}.hex` | EDHOC+OSCORE c5t handshake | sw / CC310 | CSMA / TSCH | native responder `[fd01::302:304:506:1]` |

Build: `./build-bench-rungs.sh` (matrix sw/cc310 × csma/tsch). `BENCH_ITERS`
defaults to 30 (`-DBENCH_ITERS=`); inter-iteration settle `BENCH_SETTLE_S=3`.

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

## TODO — extend to the rest of the paper's experiments
Same harness + loop pattern:
- `bench-edhoc-c5c` (inline cert), `bench-edhoc-x509` (x5chain).
- `bench-dtls-{psk,x509,c509}` — simplest loop (coap_endpoint reconnect per
  iteration; python `_serve_forever` already loops).
- `bench-enroll` — full EDHOC+OSCORE /crts+/sen CSR enrollment cycle.
Then wire each into `build-bench-rungs.sh` and add a results log.

SECURITY NOTICE: Test credentials only. Never use in production.
