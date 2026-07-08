# TSCH tests: emulator verification + expected hardware outcomes

**Purpose.** For every TSCH test we've discussed: what it does, its result in the **latest
cooja-ng emulator**, and **what to expect when running the corresponding experiment on real
hardware** (nRF52840-DK / Zolertia Firefly / nRF52840 dongle). Use this as the reference sheet
when doing the HW runs — the emulator column is the "known-good" baseline to compare against.

**SECURITY NOTICE: Test credentials only. Never use in production.**

## Summary (verified in latest cooja-ng, 2026-07-08)
- nRF TSCH association + held-sync: **PASS**
- all-nRF rxdiag TSCH (848 B RX, sync + raw-async): **PASS 12/12** — the faithful HW reference
- all-cc2538 rxdiag TSCH: **PASS** (needs our OSC/RCOSC clock fixes; first-ever in-emul)
- mixed cc2538→nRF rxdiag TSCH: **PARTIAL** — associates/DAG, 848 B blocked on cc2538 sender throughput
- cert-DTLS-x509 handshake over TSCH: **PASS**, ~4.1 s handshake latency
- **C509-vs-X509 latency over TSCH: DONE** — DTLS: no latency win (C509→DER on wire); **EDHOC:
  c5t 1.09 s « c5c 1.30 s « x5c 1.93 s** (−44 %/−33 % vs X.509) — the headline result.
  Full write-up: `TSCH-C509-VS-X509-LATENCY.md`
- TSCH energy/latency complement (task #22): **latency DONE** (above); radio duty-cycle still
  needs firmware-side energest (the plugin models CC2420 only)

**Emulator build under test:** cooja-ng-ge branch `feat/gilbert-elliott-medium` with upstream
`main` (release 0.1.1 hardening wave, `443c1f6`) merged 2026-07-08 — includes the honest-RX-CRC
change, the cc2538_gptimer + msp430/native correctness fixes, and our cc2538 clock fixes + `.nrf`
board mapping. Sanity: `arm-correctness` 153/153, full build clean.

**Firmware note:** all nRF firmware is now built on the **shared `nrf` platform**
(`TARGET=nrf BOARD=nrf52840/dk` → `build/nrf/nrf52840/dk/*.nrf`), per the platform migration. The
leaf/node images are byte-identical between emulator and HW.

---

## 0. Programming the boards (PR #3183 applied — nrfutil, from WSL)

Contiki-NG PR #3183 (Niclas Finne) migrates nrf flashing off the EOL `nrfjprog` to Rust
`nrfutil`. Cherry-picked into our tree (commits `9c9828c5e` + `5e0756731`). Both paths verified
to flash from **WSL via usbipd** (no Windows-side step needed):

| Board | Debugger | `make` target | Underlying command |
|---|---|---|---|
| **nRF52840-DK** (PCA10056) | on-board J-Link | `make TARGET=nrf BOARD=nrf52840/dk <app>.upload` | `nrfutil device program --options chip_erase_mode=ERASE_RANGES_TOUCHED_BY_FIRMWARE,verify=VERIFY_READ,reset=RESET_SYSTEM --family nrf52 --serial-number <SN> --firmware <hex>` |
| **nRF52840 dongle** (PCA10059) | none → USB DFU | `make TARGET=nrf BOARD=nrf52840/dongle <app>.upload` | `nrfutil nrf5sdk-tools pkg generate …` + `nrfutil device program --firmware <zip> --traits nordicDfu` |

Prereqs on the flashing host: `nrfutil` 8.x + `nrfutil install device` (DK) / `nrfutil install
nrf5sdk-tools` (dongle) + `jq`. Attach the probe/dongle to WSL with `usbipd attach --wsl --busid
<b>`. Device auto-selects if only one of the family is attached, else pass `NRF_UPLOAD_SN=<SN>`.

- **DK**: `nrfutil device list` should show the J-Link; the DK J-Link SN on this bench is
  **683609980**. `.upload` auto-selects a single attached DK.
- **Dongle**: enter DFU with the tiny side **RESET** button (red LED pulses; USB PID `1915:521F`
  "Open DFU Bootloader"). App mode = PID `1915:520F`. Re-`usbipd attach` after each re-enumeration.
  **VALIDATED 2026-07-07:** dongle runs shared-platform hello-world, prints over USB-CDC.

---

## TSCH test matrix

| # | Test | Emulator config | Emulator result | HW setup | Expected on HW |
|---|---|---|---|---|---|
| 1 | nRF TSCH assoc + held-sync | `cooja-ng-ge configs/test-tsch-nrf52840-dk.json` | **PASS** — assoc @0.14 s, drift 33/0/8 ppm | 2× nRF52840-DK | Both associate; leaf holds sync, periodic drift reports (a few ppm). Real XTAL drift ≤ ±40 ppm. |
| 2 | all-nRF rxdiag TSCH (848 B RX) | `rxdiag/emul-rxdiag-tsch.json` | **PASS** — `[SU]`+`[RAW]` recv 848 B **12/12**, dl-miss 0 | 2× nRF52840-DK | Leaf receives every sweep size incl. 848 B on both the sync and raw-async listeners. This is the **faithful reference** (leaf = identical nRF fw on HW+emul). On real RF expect ~11–12/12 (occasional single radio drop OK); a **systematic `[RAW]` 0/12 while `[SU]` ~12/12** = the real coap-async RX bug the ladder hunts. |
| 3 | all-cc2538 rxdiag TSCH | `rxdiag/emul-rxdiag-cc2538-tsch.json` | **PASS** — `[LEAF] reachable` (needs our OSC/RCOSC clock fixes) | 2× Firefly (or cc2538dk) | Two cc2538 nodes associate + form the DAG; leaf becomes RPL-reachable. (First-ever working cc2538↔cc2538 TSCH in-emul; on real Firefly this "just works" — cc2538 never had the emulator's RCOSC issue.) |
| 4 | mixed cc2538→nRF rxdiag TSCH | `rxdiag/emul-rxdiag-cc2538-nrf-tsch.json` | **PARTIAL** — assoc + DAG + `[LEAF] DONE`, dl-miss 0, but **848 B NOT delivered** (`[SU]`/`[RAW]` 0/12) | Firefly root + nRF-DK leaf (the rxdiag ladder, task #23) | In-emul the cc2538 **sender** can't drain 9–12 fragments fast enough over one Orchestra unicast slot (throughput-bound, not a receiver bug — see RXDIAG-MIXED-THROUGHPUT-ANALYSIS.md). On **real RF** the Firefly→nRF link has more/denser opportunities and delivered 848 B in prior HW runs; if it does NOT, suspect the same schedule-throughput limit, not the leaf. Compare leaf `[SU]` vs `[RAW]` to isolate the coap-async question. |
| 5 | DTLS-x509 handshake over TSCH | `bench/emul/emul-dtls-x509-tsch.json` | **PASS** — full handshake @34.4 s, resumed @37.7 s; **pure handshake latency ≈4.2 s** (client connects 30.25 → full PASS 34.45) | host DTLS server + nRF-DK client | Cert-DTLS completes over TSCH. The ~4.2 s x509 (36-frag) handshake latency (vs sub-second on CSMA) is the TSCH-latency headline — C509 (c5t 8-frag / c5c 17-frag) should be markedly faster. On HW the 848 B server flight is the stress point (what the rxdiag ladder isolates). |
| 6 | EDHOC c5t/c5c/x5c over TSCH | `bench/emul/emul-edhoc-{c5t,c5c,x509}-tsch.json` | **PASS all 3** — handshake latency **c5t 1.086 s « c5c 1.295 s « x5c 1.925 s** (sw uECC); see TSCH-C509-VS-X509-LATENCY.md | nRF-DK ↔ nRF-DK (2 boards) | Same monotonic ordering on HW (Orchestra schedule is firmware-defined, identical); absolute latency tracks slotframe length + real link quality. CC310 crypto path would lower the compute term but not the airtime term (task #24). |

---

## 7. TSCH energy / latency complement (task #22, paper_space/PLAN-tsch-energy-complement.md)

**Status: UNBLOCKED.** The 2026-07-01 plan marked this infeasible because in-emul TSCH was
broken (cc2538 association failed; nRF ~40× slow, no coordinator). Both are now fixed — cc2538
TSCH works (our OSC/RCOSC clock fixes) and nRF TSCH runs fast (rows 1–4 above all associate). So
the duty-cycled complement to the (CSMA-only, byte-proxy) paper energy story can now be run.

**Two measurable outputs:**
1. **Latency (the headline C509 result)** — directly measurable from the emulator run timestamps.
   Under Orchestra the root↔leaf unicast link gets ≈1 Tx slot per slotframe (~70 ms observed in
   the mixed run: consecutive fragments 70 ms apart = 7-slot period × 10 ms). A handshake of
   `N` fragments serialises to ≈`N × slot_period` + round-trips → the fragment-count gap
   (c5t 8 / c5c 17 / x509 36) becomes a **latency** gap of seconds→tens of seconds that the
   sub-second CSMA runs never show. **HW expectation:** same ordering on real DK/Firefly (schedule
   is firmware-defined, identical); absolute latency tracks the configured slotframe length.
2. **Radio duty cycle / idle energy** — the number the paper's byte-model omits (CSMA = radio
   ~always-on ≈100 % listen ≈4.6 mA; TSCH = `~1/L` listen). **Emulator caveat found 2026-07-08:**
   the built-in `energest` plugin models the **CC2420** radio only — for the nRF (ARM) firmware it
   reports 0 mJ / no duty cycle (radio-state stream not wired to the nRF radio). So in-emul
   duty-cycle needs either (a) firmware-side Contiki `energest` printed over serial (ENERGEST_TYPE_
   LISTEN/TX/CPU/LPM), or (b) a Sky/CC2420 TSCH run, or (c) the analytic `duty ≈ 1/L` from the
   slotframe. **HW expectation:** on a real DK, firmware-side energest gives the true LISTEN duty
   cycle; TSCH should be a small-few-% vs CSMA's ~100 %, i.e. 1–2 orders of magnitude lower idle
   energy — the missing term in the paper's energy budget. Crypto-compute energy is MAC-independent
   (unchanged), so its dominance over radio energy only grows under TSCH.

---

## 8. HW-only experiments (cannot run in the emulator)

| Experiment | Why HW-only | Expected outcome / how to run |
|---|---|---|
| **Firefly RPL gateway over real RF** | real 2.4 GHz RF join (emulator uses UDGM) | Firefly = RPL root/6LoWPAN gw (`zoul/firefly`), nRF52840-DK joins OTA in ~30–60 s; node appears under "Routing links" (non-storing MOP1). Docs: FIREFLY-GATEWAY-README.md. See [[project_firefly_gateway]]. |
| **rxdiag HW RX bisection ladder (R0–R6)** | the whole point is to reproduce a real-RF-only fault the emulator can't | Flash Firefly root + nRF-DK leaf (`build-rxdiag.sh` → `.hex`), capture both serials, read leaf `[SU]` vs `[RAW]`. **Compare to emulator row 2 (all-nRF 848 B 12/12).** Divergence pattern: `[SU]` ~12/12 but `[RAW]` 0/12 ⇒ generic coap-async RX drop (→R3); both drop ⇒ transport; both OK ⇒ DTLS/coap-specific (→R5). Runbook: RXDIAG-LADDER.md. |
| **CC310 hardware crypto over TSCH** | CryptoCell not emulated | Flash `bench-edhoc-{c5t,c5c}-cc310-tsch.hex` / cc310 DTLS to a DK; confirm ecdsa/ecdh/compress + record handshake timing vs the sw benches. Task #24. |
| **DK / dongle as extra TSCH nodes** | more real radios than the single-DK emulator proxy | Now flashable from WSL (§0). A dongle (`BOARD=nrf52840/dongle`) or 2nd DK can be a real leaf/hop to grow the network. |

## 9. Recommended next measurements (in-emul, to strengthen the paper)
1. **C509-vs-X509 latency over TSCH — DONE 2026-07-08** (see TSCH-C509-VS-X509-LATENCY.md).
   Two parts: **(A) DTLS** — x509 4.099 s vs native-C509 4.054 s: essentially equal, because
   Mbed TLS reconstructs C509→DER and sends **DER on the wire** (C509 is storage-only here;
   flight 756→675 B, −11 %, no latency win). **(B) EDHOC+OSCORE** — the credential is carried
   in-band, so C509 shrinks it on the wire: **c5t 1.086 s « c5c 1.295 s « x5c 1.925 s** (−44 % /
   −33 % vs X.509), monotonic in the MSG_2+MSG_3 size (204 / 509 / 960 B). **EDHOC is where the
   TSCH-latency win lives.** Needed two fixes (both local): `tsch_set_coordinator(1)` in the
   c509/EDHOC servers, and a new opt-in `EDHOC_CONF_SERVER_FROM_ROOT` so the EDHOC client
   resolves the root address dynamically (FICR-derived node IPv6 in cooja-ng-ge).
2. **Firmware-side energest duty cycle** — add ENERGEST print to a TSCH node, run in-emul (and on
   HW), record LISTEN duty cycle: TSCH few-% vs CSMA ~100 %.
3. **GE burst-loss under TSCH** — the GE medium (PR pushed) works on nRF (verified); a TSCH run
   with `medium.type=gilbert-elliott` shows loss→latency amplification (lost frame waits a whole
   slotframe). Needs per-channel GE state for full fidelity (hopping decorrelates attempts).

## Repro (all in-emul commands)
```sh
# emulator: cooja-ng-ge on feat/gilbert-elliott-medium + upstream 443c1f6, rebuilt
cd cooja-ng-ge && ./build/test_runner test configs/test-tsch-nrf52840-dk.json          # row 1
./build/test_runner test <contiki>/local-tests/rxdiag/emul-rxdiag-tsch.json            # row 2
./build/test_runner test <contiki>/local-tests/rxdiag/emul-rxdiag-cc2538-tsch.json     # row 3
./build/test_runner test <contiki>/local-tests/rxdiag/emul-rxdiag-cc2538-nrf-tsch.json # row 4
./build/test_runner test <contiki>/local-tests/bench/emul/emul-dtls-x509-tsch.json     # row 5
```
Firmware built on the shared platform: `make TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 <arm-toolchain>`.
