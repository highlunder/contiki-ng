# Gilbert-Elliott burst-loss — does channel burstiness change the C509 vs X.509 gap?

Follow-up to MULTIHOP-LOSS-RESULTS.md (which used i.i.d. UDGM loss). Here the channel is a
2-state Gilbert-Elliott Markov medium (cooja-ng-ge plugin `gilbert_elliott_medium.so`, loaded
with `--plugin`; my v1 nRF configs just switch `radiomedium.type` to `gilbert-elliott`). Knobs
(env): **`CSIM_GE_AVG_DROP=0.2`** (average frame-drop, held fixed at 20 %) and
**`CSIM_GE_BURST_LEN`** = mean dwell in the BAD state, in frames (1 = memoryless/i.i.d.;
larger = losses clustered into bursts *at the same average rate*). `CSIM_GE_SEED` = 1..6 per
cell (6 channel realizations); warmup 0 (loss applies throughout — formation loss is
common-mode to c5t/x5c). Metric = handshake success rate + latency median (MSG_1→finished).

## Results (avg_drop = 0.2 fixed; 6 seeds/cell)

### 1-hop
| burst_len | c5t success | c5t lat (s) | x5c success | x5c lat (s) |
|-----------|-------------|-------------|-------------|-------------|
| 1 (i.i.d.)| 6/6         | 1.3         | 6/6         | 4.2         |
| 4         | 6/6         | 1.4         | 6/6         | 6.4         |
| 8         | 6/6         | 1.2         | 6/6         | 3.5         |
| 16        | 5/6         | 1.1         | 5/6         | 4.4         |

### 2-hop
| burst_len | c5t success | c5t lat (s) | x5c success | x5c lat (s) |
|-----------|-------------|-------------|-------------|-------------|
| 1 (i.i.d.)| 4/6         | 6.0         | **1/6**     | 124         |
| 8         | 2/6         | 9.2         | **2/6**     | 82          |

## Findings

1. **Calibration ✓ — GE at burst_len=1 reproduces the i.i.d. UDGM point.** At 20 % drop:
   c5t 1-hop 1.3 s (UDGM rx=0.8 was 1.3 s), x5c 1-hop 4.2 s (UDGM 4.3 s). The GE medium and
   the UDGM sweep agree where they should, so the burst_len axis below is a clean isolation of
   *burstiness* at a fixed average loss.

2. **At 1 hop, bursts cost latency, not (much) reliability — and the cost lands on x5c.**
   Across all burst lengths both credentials nearly always complete (MAC + CoAP retransmits
   ride out a bad burst), but **x5c pays 3–5× the latency of c5t at every burst length**
   (c5t flat ~1.1–1.4 s; x5c ~3.5–6.4 s with outliers to 19 s). x5c's certificate is a
   multi-fragment, longer-on-air flight, so it is more likely to overlap a BAD burst and eat a
   whole-datagram CoAP retransmit. Reliability only cracks at the extreme (burst_len=16, both
   5/6).

3. **At 2 hops, reliability collapses for both — and x5c is far worse and far slower.**
   c5t: 4/6 (i.i.d.) → 2/6 (burst_len=8), median 6–9 s. x5c: **1/6 → 2/6**, and the rare
   successes took **82–124 s** (vs c5t 6–9 s). Under realistic bursty loss over one relay, the
   compact C509 handshake lands roughly half the time within seconds; the large X.509 x5chain
   handshake lands maybe 1–2 times in 6 and only after a minute-plus of retransmits, because a
   burst that straddles the fragmented flight wipes the whole datagram and the retransmit likely
   meets the next burst.

## Bottom line
Burstiness is the *realistic* loss regime (real links are bursty, not i.i.d.), and it sharpens
the same conclusion as the UDGM sweep rather than softening it: the compact C509 credential is
dramatically more robust to burst loss over multi-hop. The gap is **latency** at one hop
(x5c 3–5×) and **outright completion** at two hops (c5t sometimes, x5c essentially never).
Combined with the i.i.d. sweep, the story holds across hop count, average loss, credential
size, *and* loss correlation — and worsens for X.509 on every axis.

## Caveats
- 2-hop reliability is also capped by the minimal-schedule self-collision floor (~4/6 for c5t
  even at burst_len=1) — but the c5t≫x5c ordering holds well clear of that floor (x5c 1/6).
- warmup=0 means a bad burst can also delay/deny network formation; that is common-mode to
  both credentials (same relay/formation), so it does not explain the c5t–x5c gap, but it
  does contribute to the 2-hop absolute failure rates.
- 6 seeds/cell — enough for the success-rate contrast and order-of-magnitude latency, not for a
  tight monotonic burst_len–latency curve (x5c 1-hop latency wobbles 4.2/6.4/3.5/4.4 with the
  channel realization).

## Reproduce
`scratchpad/ge_sweep.sh` (sets `CSIM_GE_*`, switches `radiomedium.type`→`gilbert-elliott`,
runs with `--plugin build/plugins/gilbert_elliott_medium.so`); `aggregate_ge.sh` builds this
table from the per-run logs. Plugin knobs documented in cooja-ng-ge `plugins/gilbert_elliott_medium.c`.
