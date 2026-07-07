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

## Emulator limitation found: mixed CC2538 ↔ nRF TSCH does NOT converge
The literal HW pairing is a **Firefly (CC2538) root + nRF52840 leaf**. Attempting that in the
emulator **fails**, both with the `zoul-firefly` board and with the well-supported `cc2538dk`
CC2538 stand-in:
- The two nodes **associate** at TSCH (leaf hears one EB, sends data, gets a few ACKs), but the
  CC2538 root then emits **only 1 enhanced beacon and no RPL DIOs**, goes quiet ~36 s in, and
  the leaf **never becomes RPL-reachable** → no trigger, no sweep. The root does not crash
  (cycles keep accumulating); its TSCH schedule desyncs.
- Root freq 16 MHz (CC2538) vs leaf 64 MHz (nRF): cooja-ng's per-platform radio/slot timing
  models don't sustain a **mixed** cc2538↔nRF TSCH network. All shipped cooja-ng TSCH configs
  are single-platform (`test-tsch-cc2538dk.json`, `test-tsch-nrf52840-dk.json`), consistent
  with mixed TSCH being unsupported.
- Configs kept for the record: `emul-rxdiag-firefly-nrf-tsch.json`,
  `emul-rxdiag-cc2538-nrf-tsch.json` (both do not converge — do not use as a baseline).

**Why this does not weaken the baseline:** the node under test is the **nRF leaf** — identical
firmware and identical receive path in HW and emulator. The root platform only shapes fragment
inter-arrival timing on the wire; it does not change the leaf's sync-vs-async pickup, which is
the entire measured quantity. So the **all-nRF** emulator run is the faithful reference for the
leaf, and the real Firefly is used only on hardware (where mixed cc2538↔nRF works over real RF —
see `project_firefly_gateway`).

## Configs / firmwares
- Baselines (use these): `emul-rxdiag-tsch.json` (nRF-nRF TSCH), `emul-rxdiag-nrf-csma.json`
  (nRF-nRF CSMA). Both PASS.
- Firmwares: `build-rxdiag.sh` → `rxdiag-{root,leaf}-{tsch,csma}.hex` (nRF, HW+emul),
  `rxdiag-root-firefly-{tsch,csma}.bin` (Firefly HW partner). CC2538 emulator ELF via
  `make ... TARGET=cc2538dk` (`build/cc2538dk/rxdiag-root.cc2538dk`).
