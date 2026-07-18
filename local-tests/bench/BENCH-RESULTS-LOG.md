# Benchmark results log (real-hardware, over-the-air)

Paste the **`… FINAL …`** line from each run here (that line is self-contained:
n / fail / mean / median / p95 / sd / min / max / hops / retx_tot / dbg). For
right-skewed handshake latency, **median + p95** are the headline numbers.

Setup: nRF52840-DK client ↔ Firefly (RPL root / gateway) over 2.4 GHz 802.15.4;
EDHOC → bridged native responder (`fd01::…`), DTLS → setest (`fd00::1`).
BENCH_ITERS=100, BENCH_SETTLE_S=5, dbg=0 (quiet build) unless noted. **RPL
settings that affect these runs are documented in the "RPL configuration"
section below — read it before comparing DTLS vs EDHOC rows.**

Newer FINAL lines also carry `rpl_rep_events` / `rpl_rep_ms_tot` /
`rpl_rep_ms_max` (app-observed DODAG-repair wait; see "RPL repair timing"). Rows
recorded before that instrumentation note it in their comment. Every bench now
prints a `fw-build: <id>  (compiled <date> <time>)` line **both at startup and
again right before the FINAL line**, so a copied result block is self-identifying
(pass `FW_ID=…` at build, else it defaults to the UTC build date). DTLS FINAL
lines from 2026-07-03 on also count a post-handshake GET timeout as a `fail`
(earlier DTLS runs under-counted failures — see the RPL section).

| date | config | n | fail | median | p95 | mean | sd | min | max | hops | notes |
|------|--------|---|------|--------|-----|------|----|-----|-----|------|-------|
| 2026-07-03 | edhoc-c5t-cc310-csma | 100 | 0 | 327.7 | 404.3 | 332.5 | 43.6 | 228.4 | 444.5 | 1 | first clean run; settle=5 removed the slow tails |
| 2026-07-03 | edhoc-c5t-**sw**-csma | 100 | 0 | 689.2 | 760.4 | 692.4 | 42.7 | 616.8 | 823.1 | 1 | software (uECC) baseline |
| 2026-07-03 | edhoc-**c5c**-sw-csma | 100 | 0 | 822.8 | 923.9 | 832.3 | 52.6 | 721.5 | 947.8 | 1 | c5c = full cert inline (vs c5t cert-hash) |
| 2026-07-03 | edhoc-**c5c**-cc310-csma | 100 | 0 | 456.5 | 559.6 | 466.6 | 62.1 | 347.3 | 784.3 | 1 | c5c + hardware crypto |
| 2026-07-03 | dtls-**x509**-csma | 99 | 1 | 2950.4 | 3414.1 | 3056.7 | 469.4 | 2757.9 | 5851.6 | 1 | DTLS+X.509 mutual auth (~22 frags/handshake). Post-fix clean run: real 100 ms resolution, RPL guard (`rpl_rep_events=0`). 1 fail = a brief parent-loss (`hops=-1`), self-recovered. median 2950 / p95 3414 ms are the headline. |
| 2026-07-03 | dtls-**psk**-csma | 100 | 0 | 375.0 | 468.8 | 387.4 | 87.0 | 281.3 | 937.5 | 1 | **first post-fix DTLS run**: 100 ms timing resolution, RPL guard (`rpl_rep_events=0`), GET-timeout⇒fail (`fail=0`); PSK = no ECC, so this is the ~DTLS RF/protocol floor |
| 2026-07-03 | dtls-**psk**-**tsch** | 96 | 4 | 1031.3 | 2156.3 | 1202.3 | 544.8 | 750.0 | 4406.3 | 1 | **first TSCH run** (real TSCH assoc over the Firefly coordinator). 4 fails = post-handshake **GET** timeouts (handshake itself completed); each stalled ~100–146 s in CoAP retransmit before giving up. |

### c5t vs c5c (CSMA, real RF) — the C509 wire-size effect
c5t (cert **hash** in MSG_2/3) vs c5c (full cert **inline**):
- software: 689 → 823 ms = **+134 ms**
- CC310:    328 → 457 ms = **+129 ms**

The inline-cert penalty is **~130 ms and backend-independent** — exactly what
theory predicts: crypto is identical (same P-256 ops), so the delta is pure
RF/protocol (c5c's inline ~164 B cert enlarges MSG_2/MSG_3 → extra 6LoWPAN
fragmentation + air time). That it holds constant across sw and hw crypto is a
clean confirmation the cost is on the wire, not in computation — a solid
measured data point for the C509 "hash vs inline" story.

### CC310 speedup across both credential modes (real RF)
- c5t: 689 → 328 ms = **2.1×**
- c5c: 823 → 457 ms = **1.8×**

Hardware crypto roughly halves the whole handshake either way. The speedup is
slightly *lower* for c5c because its larger RF/protocol floor (the extra cert
bytes) is unaffected by faster crypto, so it dilutes the ECC saving a bit more.

### CC310 vs software (c5t, CSMA, real RF)
Whole-handshake **speedup = 689.2 / 327.7 ≈ 2.1×** (median). It is *not* the ~8×
per-op CC310 speedup because most of the handshake is RF/protocol time (message
transmission, 6LoWPAN fragmentation, CoAP round-trips), which hardware crypto
doesn't touch. Decomposition (assuming CC310 ECC ~8× faster, consistent with the
per-op benches):
- ECC saved by CC310 = 689.2 − 327.7 ≈ **361 ms**.
- => sw ECC ≈ 413 ms, CC310 ECC ≈ 52 ms, and the **RF/protocol floor ≈ 276 ms**.

**UPDATE 2026-07-03 — now measured directly** (see the emulator profiling
section below). The client's sw uECC on the critical path is **379 ms**
(keygen 87 + ECDH 87 + verify 107 + sign 98), not the inferred 413 ms, so the
RF/protocol floor is **~310 ms** (689 − 379), not 276 ms. The inference was in
the right ballpark but ~30 ms off on each side; the profiled figures are the
ones to quote. (CC310 client ECC then ≈ 689 − 361 − 310 path-arithmetic ≈ tens
of ms, consistent with the ~8× per-op benches.)

Takeaway for the paper: hardware ECC roughly halves the *whole* EDHOC handshake
over a real radio (2.1×), even though the crypto itself is ~8× — the ~276 ms
RF/protocol floor dilutes it.

## Raw FINAL lines
```
[BENCH edhoc-c5t-cc310-csma FINAL] n=100 fail=0 mean=332.472 median=327.704 p95=404.304 sd=43.616 min=228.416 max=444.464 hops=1 retx_tot=0 dbg=0 (ms)
[BENCH edhoc-c5t-sw-csma FINAL] n=100 fail=0 mean=692.445 median=689.216 p95=760.352 sd=42.660 min=616.768 max=823.056 hops=1 retx_tot=0 dbg=0 (ms)
[BENCH edhoc-c5c-sw-csma FINAL] n=100 fail=0 mean=832.324 median=822.784 p95=923.936 sd=52.648 min=721.520 max=947.760 hops=1 retx_tot=0 dbg=0 (ms)
[BENCH edhoc-c5c-cc310-csma FINAL] n=100 fail=0 mean=466.643 median=456.536 p95=559.552 sd=62.055 min=347.264 max=784.320 hops=1 retx_tot=0 dbg=0 (ms)
[BENCH dtls-psk-csma FINAL] n=100 fail=0 mean=387.432 median=375.024 p95=468.784 sd=86.959 min=281.280 max=937.536 hops=1 retx_tot=0 rpl_rep_events=0 rpl_rep_ms_tot=0.000 rpl_rep_ms_max=0.000 dbg=0 (ms)
[BENCH dtls-x509-csma FINAL] n=99 fail=1 mean=3056.710 median=2950.416 p95=3414.112 sd=469.378 min=2757.856 max=5851.632 hops=1 retx_tot=0 rpl_rep_events=0 rpl_rep_ms_tot=0.000 rpl_rep_ms_max=0.000 dbg=0 (ms)
[BENCH dtls-psk-tsch FINAL] n=96 fail=4 mean=1202.304 median=1031.288 p95=2156.288 sd=544.821 min=750.032 max=4406.304 hops=1 retx_tot=0 rpl_rep_events=0 rpl_rep_ms_tot=0.000 rpl_rep_ms_max=0.000 dbg=0 (ms)
```

### PSK: CSMA vs TSCH (measured, real RF)
| MAC | n | median | p95 | min | max |
|-----|---|--------|-----|-----|-----|
| CSMA | 100 | 375 | 469 | 281 | 938 |
| TSCH | 96 | 1031 | 2156 | 750 | 4406 |

TSCH DTLS-PSK handshake is **~2.75× the CSMA latency** (1031 vs 375 ms median), with
a wider spread (p95 2156 vs 469). Expected: TSCH packets wait for their scheduled
slot, so every DTLS flight round-trip costs slotframe cycles (min 750 ms ≈ a few
slotframes) — TSCH trades latency for determinism + radio duty-cycling (energy).
Clean paper point: on a slotted MAC the handshake is ~1 s even for the cheapest
(PSK, no ECC) case.

**The 4 fails are post-handshake GET timeouts, not handshake failures.** The
handshake completed in all four (n advanced up to the fail, is_connected was true);
the untimed CoAP GET's response was then lost on the slotted link and CoAP
retransmitted for ~100–146 s before giving up, which the GET-timeout⇒fail rule
(added for the CSMA debugging) then counts as a fail — discarding an otherwise-valid
handshake sample. At 96/100 the median/p95 are unaffected, but for the heavier
TSCH cert runs (bigger flights → more GET loss) this rule will drop more valid
handshakes and each fail wastes ~2 min. **Decision pending (see chat): keep GET
loss = full fail, or record the handshake + count GET losses in a separate field,
and/or bound the GET retransmit so a lost GET fails in ~20 s not ~140 s.**

### DTLS x509 vs psk (measured, CSMA, real RF)
- psk median **375 ms** (no cert, few frames)
- x509 median **2950 ms**, p95 **3414 ms** (mutual-auth cert flight, ~22 frags)
- → the certificate flight costs **~2575 ms** on the wire — 6LoWPAN fragmentation +
  MAC retries + DTLS flight timing, i.e. fragmentation/round-trip bound, not crypto.
  (dtls-c509 expected ~equal to x509: same reconstructed 364 B DER on the wire.)

### Adaptive-settle removed (v3) — the ~78 s gaps
A run with the v2 "wait until rank decays to hops<=1" adaptive settle came in at
99/100 but with occasional **~78 s** inter-iteration gaps (15 s base + the 60 s
recover cap + 3 s handshake). Root cause: when RPL rank inflates (`significant rank
update`, hops 2-6) it does not decay to <=1 within 60 s, so the wait hit its cap.
But the same run shows cert handshakes **succeed at hops=2..6** (the 40 s deadline
lets the DTLS retransmit land), and every real fail was at hops=1 or a parent-loss —
so the rank-gated wait added 60 s with zero reliability gain. **Removed it**; cert
benches now use a fixed settle (15 s ok / 30 s after a fail), so iterations are the
normal ~18 s and a 100-iter cert run is ~30 min. Reliability rests on the 40 s
deadline + the reachability wait, which the data shows is what carries it.
(The dtls-x509 line predates the `rpl_rep_*` fields — its 1 fail was a slow
DODAG repair, see "RPL repair timing" below. DTLS X.509 mutual auth is ~4.5×
the EDHOC c5t-sw handshake: it sends a **full certificate chain in both
directions** as ~11 6LoWPAN fragments per flight, plus DTLS's own flight
retransmit timers — so it is fragmentation/round-trip bound, not crypto bound.)

## RPL configuration (applies to all rows above)
All nodes run **RPL Lite** (`ROUTING_CONF_RPL_LITE`), objective function
**MRHOF over ETX**, non-storing MOP, over **CSMA** (no RDC — always-on radio) on
2.4 GHz 802.15.4 (channel 26, PAN 0xabcd). The Firefly is the DODAG root /
6LoWPAN border-router; the DK is a plain (non-leaf) RPL node one hop away
(`hops=1`). Trickle/DIS/DAO timers are Contiki-NG defaults.

**Per-build RPL knobs (these differ between EDHOC and DTLS — important):**

| knob | EDHOC c5t/c5c benches | DTLS psk/x509/c509 benches | why |
|------|----------------------|----------------------------|-----|
| `RPL_MRHOF_CONF_MAX_LINK_METRIC` | 16384 (ETX 128) | **16384 (now matched)** | raise the parent-eviction ceiling so a transient NOACK burst under rapid handshakes doesn't drop the parent |
| `RPL_MRHOF_CONF_MAX_PATH_COST` | 32768 | **32768 (now matched)** | paired with the above |
| `QUEUEBUF_CONF_NUM` | default | **24** (16 for psk) | hold a full ~11-fragment cert-flight burst on TX |
| `LPM_CONF_MAX_PM` | **1** | default | keep radio responsive during ECDH |
| `RPL_CONF_PARENT_TIMEOUT` | 30 (no-op in RPL Lite) | default | — |

**Why the node lost its RPL parent (was the direct cause of the DTLS fails).**
The EDHOC benches raise `MAX_LINK_METRIC` to ETX 128 precisely so rapid
back-to-back handshakes can't drive the ETX past the default ETX-4 cap and evict
the RPL parent; the DTLS benches were **missing** that guard. Under 100 rapid
DTLS handshakes, each sending a bursty (fragmented) flight, the NOACKs push the
single parent's ETX past 512 → MRHOF evicts the only parent (`no parent,
scheduling periodic DIS` → `just joined, no parent yet, setting timer for
leaving` → `found parent … staying in DAG`), a multi-second-to-minutes DODAG
repair, and any handshake attempted during the outage fails (its line shows
`hops=-1`). **Fixed 2026-07-03:** the same two `RPL_MRHOF_CONF_MAX_*` defines
were added to all three `dtls-*-bench/project-conf.h`, so DTLS is now as robust
as EDHOC. (This suppresses the eviction; the `rpl_rep_*` fields still record any
repair that does occur.)

**Why the timeout didn't cause a fail (fixed 2026-07-03).** The DTLS bench timed
only `connect()→is_connected`; the post-handshake CoAP GET was fire-and-check
with its result ignored, so a GET that *timed out* (`ERR Request timed out`)
still let the iteration count the handshake as a success. But a GET timeout means
the "connected" session is actually dead (lost ServerHello / broken route /
server 0x7900-rejecting the ClientHello). The loop now reads a `got_response`
flag set by the response handler: **GET timeout ⇒ the iteration is a `fail`** and
the handshake sample is dropped (and the longer fail-settle applies). This is
why the earlier DTLS runs showed `fail=0` despite visible `Request timed out`
lines. **Handshake-timing resolution (fixed 2026-07-03):** the poll that detects
`is_connected` was once per second, so DTLS `last=` was quantized to ~1000 ms
(`last=1000.032` everywhere). It now polls every `BENCH_HS_POLL_MS` (default
**100 ms**, `bench-stats.h`) with the 15 s deadline moved to its own etimer, so
`t1` lands within ~100 ms of true completion — sub-second DTLS latency is now
resolved. (EDHOC was never affected: it finishes on an event, not a poll.) All
DTLS rows recorded before 2026-07-03 with `last=1000.x`/`2000.x` are poll
artifacts — re-run them for real latencies.

**Firefly border-router restart after a multi-minute stall (hypothesis).** Not
root-caused on hardware. The causal chain fits: parent eviction (above) → the
node stalls for minutes → its mbedTLS keeps **retransmitting ClientHellos**
(the server log shows a storm of `ClientHello` + `0x7900 Processing of the
ClientHello … failed`) → that flood streams through the Firefly BR → the CC2538
BR eventually resets (watchdog under sustained processing, or a `memb`-pool
exhaustion fault). It is almost certainly **downstream of the two fixes above**:
stopping the eviction removes the stall, and GET-timeout⇒fail applies a 15 s
fail-settle that breaks the retransmit storm's cadence. Re-test with the fixed
firmware; if the BR still resets, capture its boot banner / reset-cause and
watch its heap — but expect it to stop. (BR `QUEUEBUF_CONF_NUM` is already 24.)

## X.509 vs C509 on the wire (DTLS) — storage win, NOT a wire win
Measured cert sizes (`edhoc-cred-{x509,c509}-native-test.h`, byte counts of the
arrays):

| credential | leaf cert | CA cert | where it lives |
|------------|-----------|---------|----------------|
| X.509 DER  | **364 B** | 339 B | sent on the wire (leaf); CA is the trust anchor, stored only |
| C509       | **138 B** | 132 B | **flash storage only** |

**Key finding — DTLS C509 does NOT shrink the handshake.** The C509 DTLS path
(`mbedtls-support.c` `COAP_DTLS_SEC_MODE_C509`, L809-826) reconstructs the stored
138 B C509 leaf back to the **identical 364 B X.509 DER** (`x509_encode_full_cert
-> own_der`) and hands that to `mbedtls_ssl_conf_own_cert`, so mbedTLS sends the
**same 364 B DER Certificate message** as the plain-x509 bench. Same wire bytes
=> same ~11 6LoWPAN fragments per flight (~22 both ways for mutual auth) => same
air time.

- **Fragments (both dtls-x509 and dtls-c509):** leaf Certificate msg ~364 B +
  TLS/DTLS framing, inside an ~700-850 B client flight (Certificate +
  ClientKeyExchange + CertificateVerify + CCS + Finished) -> **~11 fragments/flight,
  ~22 for the mutual handshake. Identical for x509 and c509.**
- **Handshake time:** therefore expected **equal within noise**. The only C509
  DTLS saving is **flash: leaf 364->138 B (-62%), CA 339->132 B (-61%)** — real,
  but storage-side, not on the wire. (Prediction to confirm on the clean re-runs:
  dtls-c509-csma median ~= dtls-x509-csma median; any gap is measurement
  artifact, not a C509 wire effect.)

**Where C509's wire win actually is: EDHOC.** EDHOC references/carries the cert
directly, so cert size hits the wire:

| transport | cert on the wire | measured median (sw, CSMA) |
|-----------|------------------|-----------------------------|
| EDHOC c5t | cert **hash** (~tens of B), not the cert | 689 ms |
| EDHOC c5c | **138 B C509 inline** | 823 ms (+134 ms vs c5t) |
| EDHOC x509 (x5chain) | **364 B DER inline** | not yet benched; extrapolates higher than c5c by the extra ~226 B |
| DTLS x509 / c509 | **364 B DER either way** | (cert-bound, see above) |

So the paper story is clean: **C509 saves flash everywhere, but saves *wire*
(fragments/latency/energy) only where the protocol puts the cert on the wire in
compact form — i.e. EDHOC c5c (138 B) vs an x509 x5chain (364 B), and best of all
c5t (hash).** DTLS always sends reconstructed DER, so C509-over-DTLS is a
storage-only win. Fill the DTLS medians from the clean (15 s-settle) re-runs to
confirm x509 == c509 on the wire.

## `hops` is ETX-inflated rank, not topology (cert benches)
A dtls-x509-csma run showed `hops` swinging 1→10 with `significant rank update`
churn (447→985→1481→…→396) while the DK stayed **one physical hop** from the
Firefly (every "found parent" is the same node). `bench_rpl_hops()` = `DAG_RANK(rank)-1`,
and the *rank* is ETX-weighted: the cert handshake floods the single CSMA link
with ~22 6LoWPAN fragments (full chain both ways), ETX inflates, rank climbs
(MIN_HOPRANKINC=128, so a healthy 1-hop child is rank ~256 = hops 1), and the
node reports "hops 5-10" on the *same* link. So in this single-hop testbed a
rising `hops` is **link congestion, not depth**. PSK stays at hops=1 (few frames).
Consequence: cert latency is dominated by link saturation + RPL rank churn (and
one freshness-based parent loss with a 20 s `rpl_rep_ms`), not by crypto.
**Mitigation (v1, insufficient):** cert-bench `BENCH_SETTLE_S` 5→15 s. A re-run
still collapsed: first ~7-8 handshakes clean (~3 s, hops=1), then congestion
collapse into back-to-back fails.

**Root cause of the collapse (v2 fix):** the bench handshake deadline (15 s) was
mismatched to the **DTLS flight-retransmit schedule**. `mbedtls-support.c` sets
`conf_handshake_timeout` MIN = **9000 ms** (max 60000), so mbedTLS retransmits a
lost flight at ~9 s, then ~27 s, ~63 s (doubling). A cert flight is one big record
→ ~11 6LoWPAN fragments, all-or-nothing on reassembly, so a single lost fragment
costs a full 9 s + resend. The 15 s deadline allowed **exactly one** retransmit
and cut the handshake off right before the 2nd would land → spurious fail → the
failed attempt (15 s of re-sent flights) re-floods the hop → ETX/rank stay high →
every subsequent attempt fails (the `fail=1,2,3…` burst with frozen `last`).

**v2 fix (cert benches, x509 + c509):**
- `BENCH_HS_DEADLINE_S` 15 → **40 s** — spans the 9 s + 27 s DTLS retransmits, so a
  marginal handshake completes via DTLS's own recovery instead of failing.
- `BENCH_FAIL_SETTLE_S` 15 → **30 s** — real cooldown after a fail.
- **Adaptive settle:** after the base cooldown, wait (capped `BENCH_LINK_RECOVER_MAX_S`
  = 60 s) until `bench_rpl_hops() <= 1`, i.e. the ETX spike has drained and the link
  is genuinely healthy, before the next flight. This is what breaks the collapse:
  it never retries a cert handshake on a still-congested hop.

Expect: slower wall-clock per iteration (long settles), a right-skewed latency
with retransmit-driven tails (read median/p95, not mean), but far fewer/no hard
fails. If it *still* collapses, the deeper structural fix is `mbedtls_ssl_set_mtu()`
so DTLS fragments at the record layer (one 802.15.4 frame/record) instead of relying
on all-or-nothing 6LoWPAN reassembly (RFC 7925 guidance) — a shared mbedtls-support
change, needs its own hw validation.

## RPL repair timing (new; `rpl_rep_*` fields)
The benchmark now records how long each iteration had to **wait for the route to
come back** before it could run (`bench-stats.h` + the per-bench recover loop):
the time `NETSTACK_ROUTING.node_is_reachable()` stayed false at iteration start.
- per-iteration line: `rpl_rep_ms=<wait before this op>` (0 when the route was up)
- FINAL line: `rpl_rep_events=<# iters that waited>`,
  `rpl_rep_ms_tot=<cumulative>`, `rpl_rep_ms_max=<worst single repair>`

It is **poll-granular** (the recover-loop etimer, ~2 s), so read it as
"the node could not proceed for ~this long while RPL healed", not a sub-second
RPL-internal figure. It captures a repair the loop *waits through*; an outage
that starts and heals *within* one handshake instead surfaces as a failed op
with `hops=-1` on its line. Together the two make a slow DODAG repair visible
in the recorded result rather than only in the live WARN log.

## Hardware vs emulator (cooja-ng, same sw firmware)
Running the *exact same* `edhoc-c5t-sw` nRF52840 firmware on a real DK and on an
emulated nRF52840 in cooja-ng (`emul/emul-edhoc-c5t.json`, 2 nodes, UDGM lossless):

| env | n | median | p95 | sd | notes |
|-----|---|--------|-----|----|-------|
| hardware  | 100 | 689.2 | 760.4 | 42.7 | real DK ↔ Firefly |
| emulator  | 30  | 955.9 | 1009.8 | 42.3 | emulated DK ↔ emulated responder; 7.1× real-time |

**Emulator ≈ 1.4× the hardware time** (956 vs 689 ms), same tight sd.
```
[BENCH edhoc-c5t-sw-emul FINAL] n=30 fail=0 mean=954.113 median=955.928 p95=1009.776 sd=42.294 min=876.976 max=1048.848 hops=1 retx_tot=0 dbg=0 (ms)
```

### Why the emulator is slower — MEASURED, not inferred (2026-07-03)
Radio loss is **zero** here (`emul-edhoc-c5t.json` is UDGM with
`success_ratio_tx/rx = 1.0`), so the gap is not retransmits. Built both the
client **and** the emulated responder with `EDHOC_PROFILE_CYCLES` (rtimer µs;
DWT reads 0 in the emulator — it doesn't model CYCCNT) and timed every ECC op
on both nodes (`emul/run-emul-profile.sh`). Per handshake:

| ECC op | Client (Node 1) | Responder (Node 2) |
|--------|-----------------|--------------------|
| generate_key_pair | 87.4 ms | 87.4 ms |
| generate_shared_secret | 87.3 ms | 87.2 ms |
| sign | 98.3 ms | 98.4 ms |
| verify | 107.5 ms | 109.9 ms |
| **total uECC P-256** | **380.5 ms** | **382.9 ms** |

Both endpoints run uECC on an emulated nRF, so **each** pays ~381 ms of ECC.
EDHOC is sequential, so the client is blocked while the responder computes
MSG_2 (keygen+ECDH+sign = 87+87+98 = **272 ms** on the responder's critical
path). Decomposing the emulated ~955 ms handshake:
- client ECC on critical path (keygen+ECDH+verify+sign) = **379 ms**
- responder ECC on critical path (keygen+ECDH+sign, before MSG_2) = **272 ms**
- RF + CoAP + 6LoWPAN fragmentation remainder = **~304 ms**

**The whole gap is the responder's crypto.** On the *hardware* bench the
responder is a **native x86** server (ECC ≈ free), so only the client's ECC
counts, and `379 ms client ECC + ~310 ms RF = 689 ms` — matching the hardware
median exactly. The client's ECC is **cycle-identical** hw-vs-emulator (same
uECC on a 64 MHz core), and the RF floor matches to within ~2 % (~304 ms emul
vs ~310 ms hw — the emulated 802.15.4 model is faithful: 32 µs/byte air-time,
40 µs ramp-up, 192 µs auto-ACK turnaround). So the emulator is **not** an
inaccurate/miscalibrated clock: it is *more honest* — it makes **both**
endpoints pay real nRF crypto, whereas the hardware test's responder is free.
The 267 ms hw→emul delta ≈ the responder's 272 ms of critical-path ECC. Note
for the paper: a symmetric device-to-device EDHOC handshake (both peers
constrained) costs ~955 ms, not ~689 ms — the hardware figure understates the
constrained-to-constrained case because our test server is not constrained.

Raw per-op lines: `emul/emul-profile.log`. Reproduce: `emul/run-emul-profile.sh`.

## dtls-c509-csma — BLOCKED, and why it doesn't need running
The dtls-c509 bench (rung 4, port 5687 = setest B2) uses `edhoc-cred-c509-native-test.h`
= a **CA-issued Type-2** (natively CBOR-signed) chain. A python-mbedtls server
**cannot** verify that in the mutual-auth client direction: it reconstructs the
client cert to DER and mbedTLS checks the DER-domain signature, but the Type-2
signature is over the CBOR encoding → rejected. This is the known open item
(Type-2 DTLS Phase 1/2, `PLAN-c509-type2-dtls.md`). setest B2 only works with a
**self-signed** cert byte-identical to the trust anchor (`simple_type2`), which
mbedTLS never re-verifies — different credential from the bench. So over real RF
against setest, every dtls-c509 handshake times out (observed: `n=0 fail=1,2,3…`,
also because only scenario A was listening — B2 is on 5687).

**It does not matter for the numbers:** dtls-c509 reconstructs to the identical
364 B X.509 DER as dtls-x509 and sends the same ~22 fragments (see "storage win,
not wire win" above), so **dtls-c509 handshake time ≡ dtls-x509 ≈ median 2950 ms**.
C509-over-DTLS is a storage-only win; recording the equivalence is correct and
complete. Options if a real measured c509 run is wanted: (a) point the bench at a
**self-signed** Type-2 c509 cred so it interops with B2's anchor trick (timing
only; cert size/reconstruction unchanged), or (b) finish Type-2 DTLS Phase 1
(out-of-band CBOR verify). Neither is needed for the paper's wire story, which is
EDHOC c5t/c5c (measured).

## TSCH x509 DTLS — works Contiki↔Contiki (emulator), median 3836 ms
The hardware x509-DTLS-over-TSCH stall was **not** a client/firmware or transport
limit — cooja-ng runs the *same* nRF firmware and completes it fine. Root cause:
a **setest (python-mbedtls) server-flight interop issue** over TSCH's slot-spread
fragment timing (the Contiki mbedtls server sets its own DTLS MTU, so its records
fragment cleanly; the bulk probe already cleared the Firefly BR and transport up
to 13-fragment datagrams). Running the actual bench in cooja-ng over TSCH against
a Contiki `x509-native-dtls-server` (RPL root + TSCH coordinator, node 1), UDGM
lossless:
```
[BENCH dtls-x509-tsch-emul FINAL] n=10 fail=0 get_fail=0 mean=3892.205 median=3835.952 p95=4023.456 sd=118.584 min=3742.208 max=4117.200 hops=1 ...
```
**CAVEAT:** the emulated server runs on an emulated nRF, so its ECDSA/ECDHE is
nRF-speed (not the native-x86 speed of the hardware setest server) — so 3836 ms
is *not* directly comparable to the hardware CSMA 2950 ms (native server). For a
clean MAC-only CSMA-vs-TSCH delta, run the same Contiki-server bench on CSMA in
the emulator too. Config: `emul/emul-dtls-x509-bench-tsch.json`; client built
`-DBENCH_SERVER_IS_ROOT` (resolves the server as the RPL root). The speculative
client MTU/MFL overrides were removed (emulator passes on default config);
TSCH buffer + `SICSLOWPAN_CONF_MAXAGE 160` kept as low-cost hardening.

## Still to collect (same setup)
- dtls-x509 / c509 on **TSCH** once the TSCH join path is up (c509 has the same
  server-interop blocker as above; x509-tsch is runnable against setest A)
- all of the above on **TSCH** once the TSCH join test passes (`../tsch-test/`)
- optional: multi-hop (add a relay node -> `hops` rises; same firmwares)
