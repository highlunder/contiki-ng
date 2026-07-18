# Exp H4 — energy measurement with the Nordic PPK2 (setup + runbook)

Task #28 / LICE `PLAN-c509-lice-followup.md` §10.4. Delivers the one metric the
paper currently derives analytically (§eval-energy is "datasheet-derived"):
**absolute mJ per handshake, mJ per enrollment op, and idle mW**, on real silicon.

Status: **not yet run.** This document is the setup + procedure; §4 lists the one
firmware addition needed before the first useful capture.

**SECURITY NOTICE: Test credentials only. Never use in production.**

---

## 1. What H4 has to produce

| output | why it matters |
|---|---|
| **mJ / handshake**, {sw, CC310} × {CSMA, TSCH} | turns the 2×2 latency table (`TSCH-HW-RESULTS.md` Result 3b) into energy. Latency ≠ energy: CC310 is ~2.05–2.60× faster but draws more while active. |
| **mJ / enrollment op** (`csr-sign`, `ca-issue`, `chain-valid`, `cert-verify`) | the energy counterpart of H1 (`ENROLL-OPS-RESULTS-LOG.md` Run 2). Also gives **mC per enrollment** for the ELA comparison (they report 39.31 mC; paper line ~780 TODO-hw). |
| **idle mW**, TSCH vs CSMA | the paper claims ~22× idle-energy saving from a *duty-cycle* measurement (Result 2: 4.58% vs ~100% radio-on). H4 converts that ratio into absolute power. |
| **I-cache energy delta** | new, cheap, and interesting: the cache cuts time ~11% but costs a little current. Net energy should still fall — worth confirming rather than assuming. |

## 2. The decision that shapes the setup: which DUT, which mode

The PPK2 has two relevant modes:

- **Source meter** — the PPK2 *supplies* the DUT (0.8–5.0 V) and measures what it
  draws. Cleanest, but the DUT must have no other power source.
- **Ampere meter** — an external supply powers the DUT and the PPK2 measures in
  series. Needs a break in the DUT's supply path to insert it.

**The conflict:** our benches report results over **USB-CDC**, and that same USB
cable powers the board. So "power the DUT from the PPK2 only" and "read the result
over USB" fight each other.

| option | DUT | mode | verdict |
|---|---|---|---|
| **A (recommended)** | **nRF52840-DK** | **Ampere meter** across the DK's current-measurement header | USB still powers the board and runs the J-Link CDC, so serial keeps working, while the PPK2 sees **only the nRF52840's** current. Isolates the SoC from the DK's regulators/LEDs/debugger. |
| B | nRF52840 dongle | Source meter on VDD | No debugger to skew the reading, but powering from the PPK2 means no USB — so no serial output. Only viable with a GPIO/LED marker and no result readback, or by accepting USB power (which defeats the measurement). |
| C | DK | Source meter via external supply pins | Requires setting the DK's power-source switch and bypassing USB power; still needs the USB cable for CDC, which reintroduces the conflict on some revisions. |

**Go with A.** It is the only option that keeps the `[BENCH …]` / `[EOP …]` result
blocks readable *while* measuring, which is what makes a capture traceable to a
`fw:`/`test:` id.

**The insertion point is the P22 "nRF current measurement" header** on the left
edge (see `paper_space/tools/nRF52840-DK layout.png`, Fig. 28; board is PCA10056
v2.0.1, SN 683609980). Its two pins are named on the silkscreen:

- **`VDD`** — the board-supply side (fed from the regulator / `nRF power source`
  switch, which sits between the J2 USB and the SoC) → **PPK2 `VIN`**
- **`VDD_nRF`** — the nRF52840 side → **PPK2 `VOUT`**

**P22 is normally closed** — by a fitted **jumper** on some boards, or the **SB40**
solder bridge beside it on others. **Inspect P22 before wiring:** if a jumper is
present, remove it and connect the PPK2 across the two pins; if there is no jumper
and SB40 is bridged, cut SB40 once to open the path. (An earlier draft of this
runbook wrongly claimed the `nRF ONLY | DEFAULT` switch, SW6, does this — it does
not; SW6 isolates the nRF power domain from the interface MCU and is a separate
function. The ammeter goes in at P22.) Powering stays via J2 USB throughout; the
PPK2 only measures.

## 3. Wiring (option A)

Available cables (photo `nRF52840-dk and PPK2.jpg`): a **2-wire red/black** lead
with 2-pin sockets, and an **8-way ribbon** — the PPK2's measurement and logic-port
cables respectively.

1. Leave the **J2 USB** (short left edge, the J-Link/IF port) plugged in — it powers
   the board and carries J-Link + the CDC serial. `nRF power source` switch on `VDD`,
   Power switch ON.
2. Open **P22** (remove its jumper, or cut SB40 — see §2).
3. Across **P22**, in **Ampere meter** mode (2-wire red/black lead):
   **PPK2 `VIN` → the `VDD` pin**, **PPK2 `VOUT` → the `VDD_nRF` pin**. Reversed, the
   app reads ~0 mA or negative — harmless, just swap. Check this first if the trace
   looks dead.
4. **PPK2 `GND` → a DK `GND` pin.** All `GND` pins are common, so one connection is
   electrically sufficient. Convenient choice: the **`GND` on the top header row that
   also carries P1.10** — that row reads `P0.27 P0.26 P0.02 GND P1.15 … P1.10 …`, so
   the `GND` sits ~5 pins left of the marker pin, serving as one common ground for
   both the ammeter and the logic port.
5. PPK2 logic **`D0` → `P1.10`** (§4/§ "Choosing the marker pin"); optionally a second
   logic `GND` on the same top row for crisper edges (not required).
6. PPK2 USB → host. In WSL: `usbipd attach --wsl --busid <ppk2>` (Nordic VID `1915`;
   the dongle shares this VID, so match by busid).
7. In the PPK2 app: **Ampere meter**, **100 kSa/s** (10 µs resolution — a ~20 ms
   CC310 op is ~2000 samples, plenty).

### Choosing the marker pin

The DK **silkscreens the GPIO name next to every header pin**, so there is no need
to know connector designators — pick a GPIO and find its label.

Use any **`P1.xx`** pin: port 1 is **entirely unused** by our firmware (verified
against `arch/platform/nrf/nrf52840/dk/nrf52840-dk-def.h` — every peripheral is on
port 0). **`P1.10`** is the default: on the **top-edge header** (layout Fig. 28), in
the row `… P1.12 P1.11 P1.10 P1.08 …` (note P1.09 is not broken out), with a `GND`
on the same row just left of `P1.15`.

Avoid, on port 0: `P0.06`/`P0.08` (UART0 TX/RX — the result blocks come out here),
`P0.13`–`P0.16` (LEDs — they draw current and would pollute the DUT reading),
`P0.11`/`P0.12`/`P0.24`/`P0.25` (buttons), `P0.17`–`P0.23` (QSPI flash),
`P0.09`/`P0.10` (NFC by default), `P0.00`/`P0.01` (32.768 kHz crystal), `P0.18`
(RESET).

Driving a PPK2 logic input costs negligible current, so the marker itself does not
meaningfully bias the measurement.

## 4. The windowing problem — read this before capturing

Energy is only meaningful over a defined window. Two problems:

- `enroll-ops-bench` runs its 50 iterations of each op **back-to-back**, so the ops
  are not separable from the current trace alone.
- A handshake's start/end are invisible to the PPK2.

`PLAN` §10.4 suggests a single-op-per-build variant (`EOP_ITERS=1`, one op enabled).
That works but needs one build per op and still leaves the window fuzzy.

**Solution: a GPIO marker on the PPK2's digital input — IMPLEMENTED.** The PPK2
samples 8 logic channels (D0–D7) *synchronously with current*, so the app shows the
marker next to the trace and the window is exact and machine-readable.

`bench-stats.h` provides `bench_marker_init/high/low()`, gated behind
`ENERGY_MARKER_PIN=<n>` (nRF **port 1**; default port overridable via
`ENERGY_MARKER_PORT`). Off by default → timing builds are byte-identical to the
logged H1/H2 runs (no GPIO write in the hot path). Wired into:

- **`edhoc-c5t-bench`** — one pulse per handshake, high right after `t0` and low
  right after `t1`, so the energy window is the same `run()→finished` region the
  RTIMER times (to within a few instructions at each edge, symmetric, so the pulse
  *width* ≈ the measured latency). Failure/deadline exits also drop the pin.
- **`enroll-ops-bench`** — **one pulse per iteration** spanning the whole 5-op
  compute sequence (build→sign→issue→chain-valid→cert-verify), not one per op. The
  ops are pure P-256/SHA-256 compute at near-constant current, so per-op energy =
  (per-iteration energy) × (the per-op time fraction from H1) — same fidelity as
  five windows, far less edit risk. (If you want to *confirm* sign and verify draw
  equal current rather than assume it, add per-op pairs; not done, as they are the
  same scalar-multiplication primitive.)

Build with the marker on (e.g. `P1.10`):
```
make -C local-tests/bench/edhoc-c5t-bench   TARGET=nrf BOARD=nrf52840/dk \
  LDFLAGS_WERROR= ENERGY_MARKER_PIN=10 <arm-toolchain>
make -C local-tests/bench/enroll-ops-bench  TARGET=nrf BOARD=nrf52840/dk \
  LDFLAGS_WERROR= ENERGY_MARKER_PIN=10 <arm-toolchain>
```

Pin choice is covered in §3 ("Choosing the marker pin"): any `P1.xx` (port 1 is
free); **`P1.10`** is the default. Never an LED (they draw current and pollute the
DUT reading).

## 5. Measurement plan

Run in this order; each builds on the last.

| # | capture | firmware | window |
|---|---|---|---|
| 1 | **idle, CSMA** | any joined CSMA node, no traffic | free-run 60 s |
| 2 | **idle, TSCH** | same node, TSCH build | free-run 60 s, *after* association (~60–70 s on real RF — Result 2) |
| 3 | **per-op**, sw | `enroll-ops-bench` + marker | one marker pulse per op |
| 4 | **per-handshake** 2×2 | `hw-2x2-icache/client-*` + marker | one pulse per handshake, ×20 |
| 5 | **I-cache delta** | rebuild 3 with `NRF_CONF_ENABLE_ICACHE=0` | same |

For each: record **mean current (mA)**, **charge (mC)** and **energy (mJ)** over the
marked window, plus the supply voltage used (state it — mJ scales with V, so a
capture at 1.8 V and one at 3.0 V are not comparable).

Use **3.0 V** unless there's a reason not to: it is a realistic coin-cell/regulated
rail and matches the datasheet figures below.

## 6. Sanity expectations (datasheet-derived — reject the capture if far off)

nRF52840 @64 MHz, 3.0 V: CPU active ≈3.3 mA; radio RX ≈4.6 mA; TX 0 dBm ≈4.8 mA;
System ON idle ≈1.5 µA.

| capture | rough expectation | from |
|---|---|---|
| sw handshake (CSMA, 1024 ms) | **≈12 mJ** | ~4 mA × 1.024 s × 3.0 V |
| CC310 handshake (CSMA, 394 ms) | **≈5–7 mJ** | shorter, but CC310 draws extra while active |
| `csr-sign` (102.6 ms) | **≈1.0 mJ** | 3.3 mA × 0.1026 s × 3.0 V |
| CC310 sign (20.4 ms) | **≈0.3 mJ** | |
| idle CSMA | **≈14 mW** | 4.6 mA × 3.0 V, radio always on |
| idle TSCH | **≈0.6 mW** | 4.58% duty (Result 2) → ≈0.21 mA |
| idle ratio | **≈22×** | should reproduce Result 2's duty ratio |

The idle ratio is the strongest cross-check: Result 2 already matched the emulator
to 0.01 pp on *duty cycle*, so if H4's TSCH/CSMA power ratio is not ≈22×, suspect
the setup (wrong header side, LED left on, debugger not isolated) before believing it.

**The interesting open question:** does CC310 win on *energy* by as much as it wins
on *latency*? It is ~2.05–2.60× faster but draws more while active, so the energy
ratio should be **smaller** than the latency ratio. If it isn't, that's a finding —
and it would be the first number here that the latency table cannot predict.

## 7. Recording

New `ENERGY-RESULTS-LOG.md`, keyed by the same **`fw:`** and **`test:`** ids as the
latency logs, so an energy row joins to its latency row. Record verbatim, plus:
supply voltage, PPK2 mode, sampling rate, DK serial (**683609980**), and the marker
pin. Note whether the I-cache was on — post-2026-07-17 builds default to **on**
(`NRF_CONF_ENABLE_ICACHE`), and the pre-fix numbers in the latency logs are not
comparable to post-fix energy captures.

## 8. Software

- **nRF Connect for Desktop → Power Profiler** — interactive; select a region and it
  reports average current and charge. Fine for first captures; the digital channels
  make the marked window selectable by eye.
- **`ppk2-api` (Python)** — for scripted, repeatable captures (20 handshakes ×4
  cells is tedious by hand). Preferable once the marker lands: trigger on D0 rising,
  integrate to falling, emit one row per window.

## 9. Prerequisites checklist

- [ ] PPK2 attached to WSL (`usbipd attach --wsl --busid <id>`; Nordic VID `1915`)
- [ ] P22 opened (jumper removed, or SB40 cut); PPK2 VIN→`VDD`, VOUT→`VDD_nRF`
- [x] Marker-pin firmware support added (§4, `bench-stats.h` + both benches); pin = `P1.10`
- [ ] Rebuild the DUT firmware with `ENERGY_MARKER_PIN=10` and wire D0 → the `P1.10` header pin
- [ ] Supply voltage decided and written down (3.0 V suggested)
- [ ] `ENERGY-RESULTS-LOG.md` created

**Next action:** the marker support is in (`bench-stats.h` + both benches, default
`P1.10`). Wire up per §3, rebuild the DUT firmware with `ENERGY_MARKER_PIN=10`, and
take capture #1 (idle CSMA vs TSCH) as a confidence check — the ~22× power ratio
should reproduce Result 2's duty-cycle ratio before moving to the per-op and
per-handshake sweeps.
