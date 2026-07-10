# M1 — EDHOC handshake latency & reliability vs hop count (C509 c5t vs X.509 x5c)

> **See also `MULTIHOP-LOSS-RESULTS.md`** for the tightened (6-seed, σ≈0) latency numbers
> and the radio-loss robustness sweep. Tightened 1-hop latency: **c5t 1.1 s, x5c 2.0 s**.
> The single-run multi-hop latencies below are superseded there by success-rate + median.


Line topology, 50 m spacing, UDGM `tx_range=55`/`interference=110` → each node reaches
only ±1 neighbour (deterministic chain). node1 = server + RPL root + TSCH coordinator;
middle nodes = relays; last node = client (resolves responder as the RPL root). Same
multi-hop client firmware at every hop count (only the node count changes). Emulator:
cooja-ng-ge (cycle-accurate ARM), single thread. Metric = client-side EDHOC handshake
wall-clock (`message_1 generation` → `Client has finished`). Credential variants:
- **c5t** = C509 by-reference (cert hash, ~8 B on the wire).
- **x5c** = X.509 x5chain, full DER certificate **inline** (~384 B, block-wise CoAP).

Prerequisite: this experiment is only runnable at all because of the **ASN-drift fix**
(`TSCH_CONF_LEAVE_ON_ASN_DRIFT 0`, see PLAN-MULTIHOP.md / tsch-conf.h). Before it, the
2nd+-tier node was evicted every slotframe and the network never extended past one hop.

## Results (3 seeds: 1, 7, 13)

| cert | hops | success | handshake latency, total (s), passing runs | median |
|------|------|---------|--------------------------------------------|--------|
| c5t  | 1    | **3/3** | 1.08, 1.13, 1.11                           | **1.11** |
| c5t  | 2    | **3/3** | 1.80, 2.54, 18.88                          | 2.54   |
| c5t  | 3    | 2/3     | 16.29, 54.99  (1 fail)                     | ~35    |
| x5c  | 1    | **3/3** | 1.98, 1.98, 2.02                           | **1.98** |
| x5c  | 2    | 2/3     | 3.66, 23.06  (1 fail)                      | ~13    |
| x5c  | 3    | **0/3** | — (never completes)                        | DNF    |

## Findings

1. **1-hop is clean, stable, and definitive.** c5t **1.11 s** vs x5c **1.98 s** (X.509
   ~1.8× slower at a single hop) — the crypto + credential-size cost with no forwarding
   noise. Tight across seeds (±0.03 s). This is the solid, quotable latency comparison.

2. **Reliability degrades with hops, and X.509 degrades FASTER.** C509 c5t completes at
   every hop count (3/3, 3/3, 2/3). X.509 x5c holds at 1 hop (3/3) but its success rate
   drops at 2 hops (2/3) and it **never completes at 3 hops (0/3)**: the 384 B certificate
   carried inline fragments into a large block-wise flight, and that flight cannot be
   reliably delivered over the 3-hop path (MSG_2 never returns, even with a 150 s
   no-progress budget). **This is the multi-hop headline: the compact C509 credential is
   the difference between the handshake completing or not, at depth.**

3. **Multi-hop latency is dominated by CoAP-CON retransmit tails, so "total" is noisy at
   depth.** e.g. c5t-2hop spans 1.8–18.9 s across seeds; c5t-3hop 16–55 s. The *core*
   MSG_1→MSG_3 span is small (c5t-3hop ~8.5 s) — most of the tail is a single lost final
   ACK forcing a ~25 s CoAP retransmit. So report multi-hop as a *reliability + trend*
   result, not a precise latency; the 1-hop numbers carry the precise latency comparison.

## Caveats / honesty
- The multi-hop numbers still have run-to-run variance and occasional failures even for
  c5t (fragmented-message delivery over the 6TiSCH **minimal** single-shared-slot schedule
  is the remaining fragility; Orchestra was tried and made things worse — see
  PLAN-MULTIHOP.md). The ASN-drift fix removed the *systematic* single-hop cap; it did not
  make deep multi-hop loss-free.
- The `-` core values from the sweep script at 2-hop are an extraction artifact (multiple
  `message_1` lines from CoAP retries confuse first-match parsing), not a real negative
  latency. Trust the `total` column.

## Reproduce
Configs `emul-{c5t,x5c}-{1,2,3}hop-tsch.json`. Runner:
`/tmp/.../run_m1_sweep.sh` (single pass) and `run_m1_reps.sh` (3-seed replication).
Firmware build recipe in PLAN-MULTIHOP.md (client `MULTIHOP_CONNECT_DELAY_S=30`,
HS deadline 150 s, CoAP CON 25 s c5t / 30 s x5c, all TSCH).
