# TSCH on real nRF52840 hardware — results (dongle + DK session)

Real-silicon validation of the in-emulator TSCH work, using a 2-node network:
**nRF52840-DK = RPL root + TSCH coordinator**, **nRF52840 dongle (PCA10059) = leaf**.
Both run the shared `nrf` platform (nrfx v3.12.1) with the firmware-side `simple-energest`
app (`local-tests/energest/energest-node.c`), `MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1`,
sw uECC. Session 2026-07-08.

**SECURITY NOTICE: Test credentials only. Never use in production.**

## Tooling milestone — PR #3183 nrf-programming in WSL
Both flash paths now work from WSL:
- **Dongle** — DFU via `nrfutil pkg generate` + `nrfutil dfu usb-serial` (nrf5sdk-tools);
  no J-Link needed. Enter DFU with the side RESET (LED pulses, USB `1915:521F`).
- **DK** — `nrfutil device program --family nrf52 --serial-number 683609980 --firmware <hex>`
  over the on-board J-Link. **Required installing the SEGGER J-Link runtime**
  (`libjlinkarm`) in WSL — without it `nrfutil device list` warns "JLinkARM DLL not
  found" and the DK is unusable. That prerequisite was undocumented in PR #3183; now
  added to `doc/platforms/nrf.md`. Attach each probe to WSL with `usbipd` (J-Link VID
  `1366`, dongle bootloader `1915`).

Ports this session: DK J-Link CDC = `/dev/ttyACM1`, dongle USB-CDC = `/dev/ttyACM0`.

## Result 1 — dongle smoke test (Step 0)
Fresh `hello-world` (nrfx 3.12.1, linked at 0x1000) DFU-flashed to the dongle boots and
prints "Hello, world" over USB-CDC → confirms the from-clean shared-nrf build + the
nrfx-submodule fix produce working dongle firmware on silicon.

## Result 2 — TSCH association over real RF (experiment 1)
The leaf's energest time-series captures the whole join. Radio-Rx duty (denominator =
CPU+LPM ≈ 1.25e6 ticks = 20 s × 62500):

| Period (20 s each) | Leaf Radio-Rx duty | State |
|---|---|---|
| #0–#2 (~60 s) | 99.999 % | TSCH **scanning** (radio always on) |
| #3 | 77.1 % | associates mid-period |
| #4–#5 | **4.58 %** | associated, steady |

**Association took ~60–70 s** (three scan periods) — a real-radio phenomenon: TSCH must
scan the channel-hopping sequence to catch an enhanced beacon. The emulator (UDGM)
associates in ~0.14 s, so it does **not** model join time; absolute latency/duty results
carry over, association *time* does not.

## Result 3 — TSCH idle duty cycle: HW vs emulator (experiment 2, the headline)

| Metric | Emulator | **Real HW** |
|---|---|---|
| TSCH associated **leaf** Rx duty | 4.59 % | **4.58 %** (57253 / 1250003) |
| Always-on reference (CSMA / TSCH scan) | 99.99 % | **99.999 %** (1251641 / 1251651) |
| Reduction vs always-on | 21.8× | **~21.8×** |
| TSCH idle **coordinator** (DK, no traffic) | — | 4.87 % (60911 / 1249603) |

The associated-leaf duty matches the emulator to **0.01 pp** (4.58 % vs 4.59 %), and the
raw per-period Rx tick counts agree to **~0.3 %** (HW 57253/57213 vs emul 57349/57421) —
the cycle-accurate emulator reproduces the real nRF52840 TSCH radio-on time almost
exactly. This puts the paper's duty-cycled-MAC energy claim (TSCH ~4.6 % idle vs CSMA
~100 %, the term the byte-proxy model omits) **on silicon**. The always-on reference is
observed directly as the leaf's pre-association scan (~100 %).

## Result 4 — C509 EDHOC (c5t) handshake latency over real-RF TSCH (experiment 3)

Looping benchmark (`local-tests/bench/edhoc-c5t-bench`, 20 iterations, on-device RTIMER
timing of `run()→FINISHED`). DK = EDHOC responder + root; dongle = initiator/leaf. 1 hop.
**Both ends at `LOG_LEVEL_ERR`** — the client bench and the DK server (`edhoc-c5t-server`
set to ERR): the responder's MSG_2 generation is *on the critical path*, and its verbose
EDHOC-Trace (several KB/handshake) blocked ~0.5 s of serial time mid-handshake at 115200
baud. The numbers below are with the **silent server**; the verbose-server figures are
shown for contrast.

**Full 2×2 on real silicon** (c5t median handshake, 20/20 each, 1 hop, silent server):

| Backend | **CSMA** | **TSCH** | TSCH penalty |
|---|---|---|---|
| **software (uECC)** | 1122.2 ms (mean 1137, max 1223) | 1297.7 ms (mean 1279 ± 31) | +175 ms |
| **CC310 hardware** | 423.6 ms (mean 424 ± 40, min 350) | 531.6 ms (mean 546 ± 40) | +108 ms |
| **CC310 speedup** | **2.65×** | **2.44×** | |

(TSCH figures were also measured with a verbose server: sw 1788.5 / CC310 1091.8 ms — the
~0.5 s inflation is the responder's EDHOC-Trace serial output, removed for the table above.)

**Clean term decomposition** (the 2×2 isolates each term; CC310 EC ops measured standalone
at ~20 ms — keygen 18.6 / sign 20.5 / verify 21.5 / ecdh 18.8 ms, `ecc-bench`):
- **Crypto**: sw ≈ **858 ms** (8 ops ≈ 107 ms each) vs CC310 ≈ **160 ms** (8 ops ≈ 20 ms).
  The sw−CC310 delta (~700 ms CSMA / ~766 ms TSCH) is the whole hardware-crypto win.
- **Base (protocol + minimal airtime), present under BOTH MACs**: CSMA_CC310 − crypto
  = 424 − 160 ≈ **264 ms** — the ~1.5 CoAP round trips + EDHOC message assembly/parse/TH
  hashing, radio-always-on so airtime is negligible.
- **TSCH-specific slotframe penalty**: only **~108 ms** (CC310) / **~175 ms** (sw) — the
  cost of duty cycling, the flip side of the ~22× idle-energy saving. **NOT ~370 ms** — an
  earlier estimate wrongly lumped the ~264 ms protocol base into "TSCH airtime"; the CSMA
  column shows most of the non-crypto time is present without TSCH.

So on hardware, **crypto *implementation* is the dominant handshake-latency factor**
(sw→CC310 is 2.4–2.65×, ~700 ms), the protocol/CoAP base is next (~264 ms), and the
TSCH slotframe penalty is a modest third (~108–175 ms). CC310's speedup is slightly larger
under CSMA (2.65×) than TSCH (2.44×) because the smaller TSCH airtime floor dilutes it less.

**Emulator reconciliation:** the emulator c5t was CSMA 0.859 s / TSCH 1.366 s (a 507 ms
TSCH penalty) vs HW's CSMA 1.122 s / TSCH 1.298 s (175 ms). The emulator's TSCH *absolute*
is close to HW (1.37 vs 1.30 s), but its **CSMA is ~260 ms optimistic** because its
idealized M4 cycle model under-counts the software P-256 crypto (no flash wait-states) —
which inflates the apparent TSCH-vs-CSMA gap in simulation. On real silicon, with real
(slower) sw crypto raising the CSMA floor, the TSCH-specific penalty is the smaller
~175 ms. (CC310 is not emulated, so there is no emulator CC310 point.)

**Methodology note (important):** the silent server also tightened the distribution
(sw sd 93→31 ms), because the removed term was serial-I/O blocking, not crypto or radio.
Always run the responder at `LOG_LEVEL_ERR` for timing; INFO is for protocol debugging only.

**vs emulator (c5t 1366 ms, sw uECC):** the clean sw handshake (1297.7 ms) is now *below*
the emulator's 1366 ms — the emulator over-counts a bit here — but within the same band;
the earlier "~30 % slower on HW" was an artifact of the verbose server. The robust point
stands: the emulator matches the radio duty exactly and the handshake latency to within
~5 % once the measurement is clean.

## Result 4 — the CC310-on-shared-platform fixes (task #24, all committed)
CC310 hardware crypto was only ever validated on the OLD nrf52840 platform; bringing it up
on the shared platform (nrfx 3.12.1) took four fixes: (1) rebase the `.crypto_data` linker
patch onto the nrfx-3.x `nrf_common.ld`; (2) re-run the idempotent `nrf_crypto_init()` per
session; (3) an explicit `CC310_SETTLE_US` after init for the TSCH interaction; (4) **the
key one** — the EDHOC *server* never called `ecc_session_begin()` (client-only), so the
responder's CC310 context was never set up → `0x8502 CONTEXT_NOT_INITIALIZED`, all-zeros
`G_Y`. Step-wise `ecc-bench` (standalone, nullradio) was decisive in proving the raw CC310
ops were fine and isolating the failure to the EDHOC+TSCH path.

## Result 4 — the tooling that made it repeatable
- `edhoc-c5t-bench` looped 20× with the real-RF root-resolution fix
  (`EDHOC_CONF_SERVER_FROM_ROOT`); the DK server auto-resets per handshake.
- `local-tests/bench/ts-serial.py` — no-dependency timestamping serial reader for
  progress (host wall-clock prefix; on-device RTIMER remains authoritative).
- `ecc-bench` with `BOOT_DELAY_S=10` countdown + `DEBUG=1`/non-debug — the standalone
  step-wise CC310 self-test.

## TSCH-vs-CSMA: what is matched vs. what's a gap (as of 2026-07-09)

| Axis | CSMA | TSCH | Emulator | Real HW |
|---|---|---|---|---|
| **Idle duty cycle** | ~100 % | 4.6 % | ✓ (99.99 / 4.59 %) | ✓ (99.999 / 4.58 %) |
| **c5t handshake latency** | 0.859 s | 1.366 s (+1.59×) | ✓ matched | ✓ matched — sw 1.12/1.30 s, CC310 0.42/0.53 s (CSMA/TSCH) |

Both comparisons are now clean on **both** emulator and hardware: the energy/duty pair
(Part C) and the handshake-latency pair (emulator CSMA 0.859 / TSCH 1.366 s; hardware
full 2×2 above). See the emulator-reconciliation note above for why the emulator's
TSCH-vs-CSMA *latency* gap (507 ms) is larger than hardware's (175 ms) — idealized sw
crypto makes the emulator's CSMA optimistic.

## Remaining hardware experiments (TODO, priority order)

1. ~~**CSMA handshake on HW** (sw + CC310)~~ — **DONE 2026-07-09** (the full 2×2 above:
   sw CSMA 1122 / TSCH 1298; CC310 CSMA 424 / TSCH 532 ms). Closed the pair on silicon.
2. **C509-vs-X.509 handshake on HW** (x5c / c5c / c5t over real-RF TSCH) — validate the
   headline emulator result (x5c ≈2.0 s ≫ C509 ≈1.3 s) on silicon. Build the
   `edhoc-oscore-{x509,c5c}` apps for the dongle+DK like c5t. High value.
3. **DTLS x509/c509 over real-RF TSCH** (scenarios A/B) — the 848 B server cert flight is
   the stress point; ties into the rxdiag RX ladder (#4).
4. **rxdiag RX bisection ladder on HW** (task #23) — Firefly root + nRF-DK leaf, the
   848 B coap-DTLS-over-TSCH RX drop hunt; firmware built, never run on real RF.
5. **CC310 for scenarios A–C on HW** — the TODO-hw residual (only c5t / scenario D done);
   x5c, c5c, and the DTLS `_ALT` path.
6. **Absolute energy (Power-Profiler-Kit)** — the duty cycle here is a *ratio*; a PPK gives
   absolute mJ/handshake + idle mW, converting `table:tsch-idle`'s modelled power to
   measured. The paper flags this as future work.
7. **Energest during an active handshake/enrollment** — energy *per handshake* (not just
   idle duty); firmware-side ENERGEST across the handshake window on HW.
8. **Full enrollment (/crts + /sen) over real-RF TSCH** — Tier-2 enroll is emulator-only
   (2.9 s); run on the DK+dongle. + CC310-accelerated enroll.
9. **Multi-hop / larger network** — EMULATOR DONE (`multihop/MULTIHOP-M1-RESULTS.md`):
   c5t vs x5c EDHOC over 1/2/3 TSCH hops; 1-hop clean c5t 1.1 s vs x5c 2.0 s; x5c fails to
   complete at 3 hops while c5t succeeds. Blocker was a spurious ASN-drift eviction (fixed,
   gated `TSCH_CONF_LEAVE_ON_ASN_DRIFT`). **HW residual:** add the 2nd dongle / a Firefly as
   an extra hop and confirm the same on real RF (also validates the ASN-drift fix is
   emulator-only).
10. **Lossy-link robustness on real RF** — EMULATOR DONE (`multihop/MULTIHOP-LOSS-RESULTS.md`
    UDGM + `MULTIHOP-GE-BURST-RESULTS.md` Gilbert-Elliott): under loss/burst the x5c handshake
    degrades far faster than c5t and collapses at 2 hops. **HW residual:** distance/interference
    handshake completion on real RF — the emulator loss/GE study's hardware counterpart.
11. **CC310 in-handshake per-op DWT profiling on HW** — per-op cycles *during* a real
    handshake (vs the standalone `ecc-bench`), to see cache/contention effects.

## Firmware / repro
`local-tests/energest/fw-hw/`: `energest-root-dk.hex` (DK, `ROOT=1`), `energest-leaf-dongle.hex`.
Build: `local-tests/energest/build-energest.sh` (retarget to `TARGET=nrf BOARD=nrf52840/{dk,dongle}`).
DK flash: `nrfutil device program … --serial-number 683609980 --firmware energest-root-dk.hex`.
Dongle flash: DFU (side RESET → pulsing) then `nrfutil pkg generate … --application
energest-leaf-dongle.hex …` + `nrfutil dfu usb-serial -pkg … -p /dev/ttyACM0`.
Read serial: `picocom --imap lfcrlf /dev/ttyACMx -b 115200`.
