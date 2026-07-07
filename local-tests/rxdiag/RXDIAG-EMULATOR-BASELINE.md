# rxdiag — emulator baseline (what the hardware runs are compared against)

**SECURITY NOTICE: Test credentials only. Never use in production.**

All runs: cooja-ng-ge `test_runner` (branch `feat/gilbert-elliott-medium`, merged to
upstream/main `d4c7b73` on 2026-07-04), UDGM lossless medium, `seed=1`. The leaf
(node under test) is the **same nRF52840 firmware** used on hardware. Per-size counts are
receives over 3 trigger rounds × 4 trials = **12 expected** per size, per path.

## Baseline result (the comparison reference)

### nRF root + nRF leaf, **TSCH**
| size | frags | `[SU]` sync | `[RAW]` async |
|-----:|------:|-----:|------:|
| 700  | 8  | 12 | 11 |
| 760  | 9  | 12 | 12 |
| 820  | 10 | 12 | 12 |
| **848** | **10** | **11** | **12** |
| 880  | 10 | 12 | 12 |
| 920  | 11 | 12 | 12 |
| 1000 | 12 | 12 | 12 |

truncated/clobbered (len ≠ claimed): **SU=0, RAW=0**

### nRF root + nRF leaf, **CSMA** (rung R4 control)
| size | frags | `[SU]` sync | `[RAW]` async |
|-----:|------:|-----:|------:|
| 700  | 8  | 11 | 11 |
| 760–1000 | 9–12 | 12 | 12 |

truncated/clobbered: **SU=0, RAW=0**

## Interpretation — what "normal" looks like
On the emulator, the **raw async (`[RAW]`, coap-uip-like) path is as reliable as the sync
(`[SU]`) path at every size, including 848 B, on both TSCH and CSMA**, with **zero
truncation**. The stray 11/12 cells are a single radio-level datagram drop that hits **one
path on one size** — not a systematic path failure, and it is *not* correlated between paths
or reproducible at 848 B specifically.

**This is the reference the hardware ladder is measured against.** The HW fault would show as a
**divergence from this baseline**:
- `[SU]` gets 848 B ≈ 12/12 but `[RAW]` gets it **0/12 (or truncated)** → the async receive
  path drops large reassembled datagrams on real TSCH (rung R2 "reproduced" branch → R3).
- Both paths get 848 B on HW too → the fault is *not* in the generic async RX path; it is
  DTLS/coap-specific (rung R2 "async fine" branch → R5).

Because the emulator shows **no** such divergence (as expected — the bug is real-RF/TSCH-timing
specific), the emulator cannot localize the fault; it only fixes the "known-good" reference.

## Mixed CC2538 ↔ nRF TSCH — now converges (2026-07-07); residual is sender throughput
**Superseded earlier claim.** This section previously stated mixed cc2538↔nRF TSCH "does not
converge" and blamed cooja-ng's per-platform slot-timing / the 16-vs-64 MHz difference. That was
wrong on both counts. Three cc2538 **clock-emulation bugs** in
`cooja-ng-ge/src/arm/cc2538_sys_ctrl.c` were the real cause (CLOCK_CTRL.OSC bit position; OSC32K
stabilization; the RCOSC CPU-frequency downshift — see
`cooja-ng-ge/CC2538-TSCH-CLOCK-FINDING.md`). With them fixed:
- **all-cc2538 TSCH passes** (`emul-rxdiag-cc2538-tsch.json`: both nodes steady 16 MHz, 0 dl-miss,
  `[LEAF] reachable`).
- **mixed cc2538-root + nRF-leaf now associates, forms the DAG, and reaches `[LEAF] DONE` with 0
  dl-miss** — the pairing converges. The "16 MHz cc2538 vs 64 MHz nRF" difference is real and fine;
  it never was the problem.

**Remaining gap: the 848 B sweep is not delivered over the mixed link — a cc2538 SENDER issue.**
The cc2538 root emits **no frame larger than 96 B**; the leaf receives nothing at the app layer.
Root-caused to two sender-side effects (both on the cc2538 root; the nRF leaf receive path is not
implicated — it accepts the same sizes fine from an nRF sender):
1. **Output-fragmentation buffer starvation (fixed).** `rxdiag`'s `project-conf.h` trimmed the
   cc2538 pools to fit 32 KB SRAM with `QUEUEBUF_CONF_NUM 6`, on the (wrong) assumption that "the
   sender doesn't reassemble, so trimming is harmless." But 6LoWPAN **output** allocates one
   queuebuf per fragment up front and **drops the whole datagram** if `queuebuf_numfree() < frags`
   (`[WARN: 6LoWPAN] output: dropping packet, not enough free bufs`). The 700..1000 B sweep needs
   9..12 queuebufs, so with 6 free, every large datagram was silently dropped before any fragment
   hit the air. Fixed by sizing the sender's output pools for the worst case
   (`QUEUEBUF_CONF_NUM 16`, `TSCH_QUEUE_CONF_NUM_PER_NEIGHBOR 16`); the leaf then receives 700 B.
2. **TSCH unicast throughput bottleneck (residual, not a pool-size issue).** Even so, 848 B still
   fails: cc2538→nRF TSCH unicast drains fragments slower than the sweep queues them (a new 9..12
   fragment datagram every ~1.5 s), so a backlog holds most queuebufs and the free count plateaus
   at ~`needed-1`. Raising `QUEUEBUF_CONF_NUM` to 24 did **not** help (free plateaus higher but
   still one short; 700 B delivers, 848 B does not) — proving the blocker is drain rate, not buffer
   count. Closing it needs a slower sweep cadence or a denser TSCH unicast schedule
   (more Tx slots to the leaf) — deferred as rxdiag-harness tuning.

**Why none of this weakens the baseline:** the node under test is the **nRF leaf** — identical
firmware and identical receive path in HW and emulator, and it is *not* the bottleneck here (the
gap is entirely on the cc2538 sender). The all-nRF run remains the faithful reference for the
leaf's sync-vs-async pickup. Real Firefly is used on hardware, where mixed cc2538↔nRF delivers
over real RF (see `project_firefly_gateway`).
- Configs: `emul-rxdiag-cc2538-nrf-tsch.json` (converges; 848 B blocked on sender throughput),
  `emul-rxdiag-firefly-nrf-tsch.json` (zoul-firefly variant).

## Configs / firmwares
- Baselines (use these): `emul-rxdiag-tsch.json` (nRF-nRF TSCH), `emul-rxdiag-nrf-csma.json`
  (nRF-nRF CSMA). Both PASS.
- Firmwares: `build-rxdiag.sh` → `rxdiag-{root,leaf}-{tsch,csma}.hex` (nRF, HW+emul),
  `rxdiag-root-firefly-{tsch,csma}.bin` (Firefly HW partner). CC2538 emulator ELF via
  `make ... TARGET=cc2538dk` (`build/cc2538dk/rxdiag-root.cc2538dk`).
