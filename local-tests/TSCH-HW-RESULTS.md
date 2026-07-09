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
timing of `run()→FINISHED`, minimal `LOG_LEVEL_ERR` output so serial does not perturb
timing). DK = EDHOC responder + root; dongle = initiator/leaf. 1 hop.

| Backend | n (ok/fail) | median | mean ± sd | p95 | min–max |
|---|---|---|---|---|---|
| **software (uECC)** | 20 / 0 | **1788.5 ms** | 1798.8 ± 93.0 ms | 1996.8 ms | 1720.9–2067.9 ms |
| CC310 hardware | _pending_ | | | | |

**vs emulator (c5t 1366 ms, sw uECC):** real hardware is **~30 % slower** on the sw path.
This is the complement of the duty-cycle match: the emulator reproduces the *radio*
timing exactly (duty to 0.01 pp — a ratio), but the *handshake latency* carries ~8
software P-256 ops whose cost the emulator's cycle model under-counts (idealized M4, no
flash wait-states), plus real-RF slot/ACK timing. So absolute EDHOC latency is ~30 %
optimistic in-emulator while the ordering (and the fragment-count → airtime structure)
holds. 0 retransmits over the clean single-hop link; the ~93 ms sd is slot-alignment
jitter (each handshake catches a slightly different slotframe phase), consistent with the
analytic `T_frag ≈ 100 ms` per fragment.

## Result 4 — the tooling that made it repeatable
- `edhoc-c5t-bench` looped 20× with the real-RF root-resolution fix
  (`EDHOC_CONF_SERVER_FROM_ROOT`); the DK server auto-resets per handshake.
- `local-tests/bench/ts-serial.py` — no-dependency timestamping serial reader for
  progress (host wall-clock prefix; on-device RTIMER remains authoritative).

## Firmware / repro
`local-tests/energest/fw-hw/`: `energest-root-dk.hex` (DK, `ROOT=1`), `energest-leaf-dongle.hex`.
Build: `local-tests/energest/build-energest.sh` (retarget to `TARGET=nrf BOARD=nrf52840/{dk,dongle}`).
DK flash: `nrfutil device program … --serial-number 683609980 --firmware energest-root-dk.hex`.
Dongle flash: DFU (side RESET → pulsing) then `nrfutil pkg generate … --application
energest-leaf-dongle.hex …` + `nrfutil dfu usb-serial -pkg … -p /dev/ttyACM0`.
Read serial: `picocom --imap lfcrlf /dev/ttyACMx -b 115200`.
