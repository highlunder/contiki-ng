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

| Backend | n (ok/fail) | median | mean ± sd | p95 | (verbose server) |
|---|---|---|---|---|---|
| **software (uECC)** | 20 / 0 | **1297.7 ms** | 1279.0 ± 31.2 ms | 1300.2 ms | 1788.5 ms |
| **CC310 hardware** | 20 / 0 | **531.6 ms** | 546.4 ± 40.3 ms | 631.2 ms | 1091.8 ms |

**CC310 gives a 2.44× whole-handshake speedup** over real-RF TSCH (1297.7 → 531.6 ms, a
766 ms saving). Decomposition: CC310 EC ops measured standalone at ~20 ms each
(keygen 18.6 / sign 20.5 / verify 21.5 / ecdh 18.8 ms — `ecc-bench`), so the ~8-op crypto
floor is ~160 ms; the remaining ~370 ms of the CC310 handshake is **airtime** (the real-RF
fragment×slot floor). The software handshake's ~930 ms of crypto (≈116 ms/op uECC @ 64 MHz)
is what CC310 collapses — a **~5.8× per-op** speedup that dilutes to 2.44× on the whole
handshake because airtime is a fixed, MAC-governed floor crypto cannot touch. This is the
hardware-crypto analogue of the paper's "signature/crypto cost dominates, wire format is
secondary" finding: here crypto *implementation* (hw vs sw) governs handshake latency, with
airtime as the residual.

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

## Firmware / repro
`local-tests/energest/fw-hw/`: `energest-root-dk.hex` (DK, `ROOT=1`), `energest-leaf-dongle.hex`.
Build: `local-tests/energest/build-energest.sh` (retarget to `TARGET=nrf BOARD=nrf52840/{dk,dongle}`).
DK flash: `nrfutil device program … --serial-number 683609980 --firmware energest-root-dk.hex`.
Dongle flash: DFU (side RESET → pulsing) then `nrfutil pkg generate … --application
energest-leaf-dongle.hex …` + `nrfutil dfu usb-serial -pkg … -p /dev/ttyACM0`.
Read serial: `picocom --imap lfcrlf /dev/ttyACMx -b 115200`.
