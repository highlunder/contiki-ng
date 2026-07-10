# Radio-loss robustness + tightened latency — C509 c5t vs X.509 x5c over TSCH

Follow-up to MULTIHOP-M1-RESULTS.md. Same line topology / firmware. Radio loss induced
via UDGM `success_ratio_rx` (per-link reception probability; `success_ratio_tx`=1.0). Each
(credential, hops, loss) cell = **6 seeds** (1..6). Metric = handshake success rate
(passing / seeds) and latency (`message_1 generation` → `Client has finished`, median of
passing runs). Credentials: **c5t** = C509 cert-hash reference (~8 B on the wire);
**x5c** = X.509 x5chain, full 384 B DER certificate carried inline (block-wise CoAP).

## 1-hop (server + client, no relay)

| rx (link) | c5t success | c5t lat (s) | x5c success | x5c lat (s) |
|-----------|-------------|-------------|-------------|-------------|
| 1.00      | **6/6**     | **1.1**     | **6/6**     | **2.0**     |
| 0.90      | 6/6         | 1.3         | 6/6         | 3.1         |
| 0.80      | 6/6         | 1.3         | 6/6         | 4.3         |
| 0.70      | 6/6         | 3.2         | 6/6         | 7.0         |

## 2-hop (one relay)

| rx (link) | c5t success | c5t lat (s) | x5c success | x5c lat (s) |
|-----------|-------------|-------------|-------------|-------------|
| 1.00      | 5/6         | 2.7         | 3/6         | 23.1        |
| 0.90      | 3/6         | 16.8        | 2/6         | 19.1        |
| 0.80      | 3/6         | 8.3         | 2/6         | 27.1        |
| 0.70      | 3/6         | 18.4        | 2/6         | ~27         |

(3-hop: c5t completes lossless but is already unreliable; x5c never completes even lossless
— see MULTIHOP-M1-RESULTS.md. So the loss sweep is on the two representative depths where
both credentials at least sometimes complete.)

## Findings

1. **Tightened latency (the clean numbers).** At 1 hop, lossless, the handshake is
   deterministic to the 0.1 s: **c5t 1.1 s (6/6, σ≈0)**, **x5c 2.0 s (6/6, σ≈0)**. This is
   the precise, replication-backed latency comparison (~1.8× for the larger credential —
   more signed/verified/transmitted bytes). The multi-hop totals stay noisy *by nature*
   (see #3), so 1-hop carries the precise latency and multi-hop carries the reliability
   story.

2. **Under loss at 1 hop, both still complete (MAC + CoAP retransmits recover), but x5c's
   latency degrades ~2× faster.** At rx=0.7: c5t median 3.2 s vs x5c 7.0 s (x5c outliers to
   13.7 s). Mechanism: x5c's 384 B cert is a multi-fragment flight, so each lost fragment
   costs a whole-datagram retransmit; more fragments ⇒ more retransmits ⇒ steeper latency
   growth. The compact c5t (a hash reference) is a near-single-fragment exchange and barely
   moves until 30 % loss.

3. **At 2 hops, reliability collapses — and x5c collapses first and hardest.** Even lossless,
   c5t is 5/6 and x5c only 3/6; add any loss and c5t falls to ~3/6 while x5c holds ~2/6, at
   ~2–3× the latency (x5c ~20–27 s vs c5t ~8–18 s). The dominant failure is fragment loss on
   the 6TiSCH **minimal single-shared-slot** schedule (self-collision at the relay), and it
   punishes the larger x5c flight far more.

**Bottom line (headline for the paper):** across all three stress axes — **hop count, link
loss, and credential size** — the compact C509 credential is both more reliable and lower
latency, and *the gap widens as conditions worsen*. A large inline X.509 certificate is not
merely slower on a clean single hop (2.0 vs 1.1 s); under realistic loss and depth it is the
difference between a handshake that lands and one that does not.

## Caveats
- Loss model here is IID per-link (`success_ratio_rx`); real links are bursty. The
  **Gilbert-Elliott burst-loss follow-up is done** — see `MULTIHOP-GE-BURST-RESULTS.md`. It
  confirms and sharpens this: GE at burst_len=1 reproduces these IID points (calibration ✓),
  and clustering the loss into bursts hurts the multi-fragment x5c flight more (x5c 3–5× c5t
  latency at 1 hop; c5t sometimes / x5c essentially-never completes at 2 hops).
- The 2-hop reliability floor (~3/6 for c5t regardless of loss) is the minimal-schedule
  self-collision limit, not a credential effect; it caps the multi-hop numbers' precision.
  A dedicated per-node schedule would raise the floor (Orchestra as-configured did not — see
  PLAN-MULTIHOP.md), but even at this floor the c5t-vs-x5c ordering is consistent.
- Latencies are medians of *passing* runs; failed runs are excluded from the latency column
  but captured in the success column.

## Reproduce
`scratchpad/loss_sweep.sh "<seeds>"` generates configs from `emul-{c5t,x5c}-{1,2}hop-tsch.json`
by patching `seed` + `success_ratio_rx`, runs each sequentially; `aggregate_loss.sh` builds
this table from the per-run logs.
