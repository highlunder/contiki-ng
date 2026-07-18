# Does issue #4 (mixed cc2538→nRF 848 B non-delivery) show on real hardware?

**SECURITY NOTICE: Test credentials only. Never use in production.**

Analysis 2026-07-07. Question: the residual after the QUEUEBUF fix — the mixed
cc2538-root → nRF-leaf link not delivering the 848 B fragmented sweep — is it a real
hardware phenomenon or an emulator/synthetic-test artifact? Investigate solutions.

## TL;DR
Issue #4 is **two independent effects** with opposite hardware implications:
1. **6LoWPAN output-buffer sizing** — **REAL on hardware, and already fixed.** Any cc2538
   (Firefly) sender/forwarder needs `QUEUEBUF_CONF_NUM ≥ the datagram's fragment count`
   (9–12 for a 700–1000 B flight) or 6LoWPAN drops the whole datagram before it hits the
   air. Trimming to 6 (as the old `project-conf.h` did) breaks real HW too.
2. **A genuine cross-platform cc2538→nRF unicast fragment-delivery failure** — **REAL on
   hardware** (firmware/schedule-determined, so identical on HW and emulator), and NOT the
   synthetic sweep-pipelining artifact it first looked like. This is the important finding.

## Evidence
All three runs: same firmware, lossless UDGM medium, `seed=1`, `dl-miss = 0` throughout
(so TSCH sync is NOT the issue).

| Sweep cadence | 848 B delivered | notes |
|---|---|---|
| 1.5 s (default) | 0 | buffers plateau at ~needed-1 |
| **5 s isolated** (models DTLS stop-and-wait) | **[SU] 1×, [RAW] 0×** | still sparse |

The decisive measurement is at 5 s isolation (each datagram effectively alone):
- **~65 datagrams passed the buffer check and had ALL their fragments transmitted by the
  root, but only 8 reassembled at the leaf** — i.e. **57 fully-transmitted datagrams were
  lost, on a lossless medium.** (514 large fragments left the root's radio; 8 app
  deliveries.)
- Buffers *do* recover (free fluctuates 1→10), so it is not a hard queuebuf leak; and
  isolating datagrams did NOT fix delivery — so the residual is **not** the back-to-back
  pipelining (that part *was* synthetic) and **not** buffer count.
- The very first datagram of a sweep drains cleanly at ~70 ms/fragment (one Orchestra
  unicast Tx slot every 7 × 10 ms) and delivers; subsequent ones stall irregularly.

Conclusion: fragments are transmitted but largely **not received/ACKed** at the nRF leaf
(consistent with retransmission inflation from un-ACKed unicast frames), specific to the
**cc2538↔nRF mix** — an all-nRF pair delivers every size 12/12. Because a lossless medium
still loses them, the cause is a **scheduling/ACK interaction between the two platforms'
TSCH implementations**, not RF loss.

## Would it show on real HW?
- **Buffer sizing:** yes, unconditionally (same code path). Fixed.
- **Cross-platform unicast delivery:** yes — it is schedule/firmware-determined and the HW
  runs the *same* firmware, so a real Firefly forwarding an 848 B DTLS flight to an nRF over
  TSCH would be **slow and unreliable** the same way. This overlaps the exact phenomenon the
  rxdiag ladder was built to localize (a large fragmented flight that does not get picked up
  on the receive side), and it appears here **without** real-RF loss — a strong hint that the
  HW fault may have a scheduling/ACK component, not only RF loss.
- **Caveat / what is synthetic:** the *sweep’s* back-to-back cadence is not how DTLS behaves
  (DTLS is stop-and-wait per flight); that part is a test artifact. But isolating the
  datagrams did not restore reliable delivery, so the underlying cross-platform issue is real.

## Solutions to investigate (ranked)
1. **Confirm the mechanism first (cheap, do before fixing).** Instrument the cc2538 root and
   nRF leaf TSCH unicast link: per-neighbor queue occupancy, TX attempts vs ACKs, and the
   actual Tx-slot (root) vs Rx-slot (leaf) offsets for the root↔leaf link. Hypothesis to
   confirm/refute: the leaf is not ACKing the root's unicast fragments because the two
   platforms' Orchestra unicast slots for that link do not align (note the interplay of
   `ORCHESTRA_ROOT_PERIOD=7` vs `ORCHESTRA_UNICAST_PERIOD=17`, both defaults here).
2. **Align the schedule.** Force both ends to the same Orchestra rule + period (e.g. pin
   `ORCHESTRA_CONF_UNICAST_PERIOD` and disable the special root period), or fall back to a
   shared-slot schedule so fragments are not stuck waiting for a rarely-aligned dedicated
   slot. This is the most likely direct fix if step 1 confirms misalignment.
3. **Denser / more-robust unicast schedule.** More Tx slots to the leaf (shorter unicast
   period or a dedicated link) raises the effective drain rate and shortens a flight's
   time-on-wire below the leaf's reassembly `MAXAGE`. Cost: higher radio duty cycle/energy on
   real constrained HW — quantify against the energy budget.
4. **Shrink the flight below the fragmentation cliff** — directly aligned with this project's
   thesis. A C509-compressed certificate chain fragments into fewer 802.15.4 frames than the
   equivalent X.509 flight, so it is inherently more robust to this exact unicast-delivery
   fragility. Worth measuring: fragment count and mixed-link delivery for C509 vs X.509
   flights (700 vs ~450 B etc.).
5. **Receiver reassembly robustness (already partly done).** Leaf keeps `SICSLOWPAN_MAXAGE
   160` (~10 s) and 24 fragment buffers — keep these generous so a slow flight still
   reassembles; verify the window covers the measured drain time.
6. **Test-faithfulness only:** a stop-and-wait sweep cadence (wait for the TSCH queue to
   drain before the next datagram) models DTLS correctly and removes the synthetic pipelining
   — but per the evidence above it will NOT by itself make the mixed 848 B pass, so it is a
   test-hygiene change, not the fix.

## Relationship to the ladder's goal
The faithful leaf reference remains **all-nRF** (identical leaf firmware/receive path HW+emul;
delivers 848 B 12/12). This mixed-link cross-platform delivery issue is a *separate, newly
exposed* lead that is worth pursuing precisely because it reproduces a receive-side large-flight
failure in the emulator without RF loss — something the all-nRF baseline never does.
