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

**Good news: no cutting or soldering is needed.** The bench board
(photographed in `paper_space/tools/nRF52840-dk and PPK2.jpg`) is a **PCA10056
v2.0.1, SN 683609980** — the same DK used for H1/H3 — and it carries a dedicated
current-measurement path:

- a **`nRF ONLY | DEFAULT`** slide switch (top edge of the board), and
- a **`nRF meas`** 2-pin header on the left edge (next to `VDD`), i.e. **P22**.

In `DEFAULT` the two P22 pins are connected and the board runs normally. Moving the
switch to **`nRF ONLY`** breaks the nRF52840's supply out to that header so an
ammeter can be inserted, leaving the interface MCU, LEDs and regulators powered
separately — exactly the isolation this measurement needs. Confirm the switch/header
semantics in the *nRF52840 DK User Guide* for v2.0.1 before the first capture, but
there is no solder bridge to cut on this revision.

## 3. Wiring (option A)

Available cables (same photo): a **2-wire red/black** lead with 2-pin sockets, and an
**8-way ribbon** with individual sockets — the PPK2's measurement and logic-port
cables respectively.

1. DK powered from USB as usual (`nRF power source` switch on `VDD`, power switch ON).
2. Slide **`nRF ONLY | DEFAULT` → `nRF ONLY`**.
3. Across the **`nRF meas` (P22)** header, in **Ampere meter** mode:
   **PPK2 `VIN` → the supply side**, **PPK2 `VOUT` → the nRF side**. Reversed, the
   app reads ~0 mA — a harmless but confusing failure, so check this first if the
   trace looks dead.
4. **PPK2 `GND` → any DK `GND` pin** (several are silkscreened `GND` along both
   edges). Ampere-meter mode needs this third connection; the 2-wire lead only
   carries VIN/VOUT, so take GND from a spare ribbon wire.
5. PPK2 logic port **`D0` → the marker GPIO** (§4) and a logic-port **`GND` → DK
   `GND`**.
6. PPK2 USB → host. In WSL: `usbipd attach --wsl --busid <ppk2>` (Nordic VID `1915`).
7. In the PPK2 app: **Ampere meter**, **100 kSa/s** (10 µs resolution — a ~20 ms
   CC310 op is ~2000 samples, plenty).

### Choosing the marker pin

The DK **silkscreens the GPIO name next to every header pin** (`P0.03`, `P1.10`, …),
so there is no need to know connector designators — pick a GPIO and find its label.

Use any **`P1.xx`** pin: port 1 is **entirely unused** by our firmware (verified
against `arch/platform/nrf/nrf52840/dk/nrf52840-dk-def.h` — every peripheral is on
port 0). **`P1.10`** is a good default.

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

**Better: a GPIO marker on the PPK2's digital input.** The PPK2 samples 8 logic
channels (D0–D7) *synchronously with current*, so the app shows the marker next to
the trace and the window becomes exact and machine-readable.

**Firmware addition needed** (not yet written): raise a pin before the timed region
and drop it after — the same region `bench_elapsed_us()` already brackets, so
energy and latency measure *identically defined* windows. Contiki's GPIO HAL has
what's needed (`gpio_hal_arch_port_set_pins` / `..._clear_pins`, see
`arch/cpu/nrf/dev/gpio-hal-arch.c`). Suggested shape:

```c
/* PPK2 D0 marker: high for exactly the region the RTIMER also times, so the
 * energy window and the latency window are the same region by construction. */
#ifdef ENERGY_MARKER_PIN
#define MARK_HIGH() gpio_hal_arch_port_set_pins(0, 1UL << ENERGY_MARKER_PIN)
#define MARK_LOW()  gpio_hal_arch_port_clear_pins(0, 1UL << ENERGY_MARKER_PIN)
#else
#define MARK_HIGH() do {} while(0)
#define MARK_LOW()  do {} while(0)
#endif
```
Gate it behind `ENERGY_MARKER_PIN=<n>` so timing builds stay byte-identical to the
ones already logged (a GPIO write inside a timed region would perturb H1/H2 by a few
cycles — negligible, but there is no reason to invalidate the existing blocks).

Pick a pin that is **not** an LED (LEDs draw current and would pollute the DUT
measurement) and not used by the radio/UART — an unused header pin on P3/P4.

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
- [ ] `nRF ONLY | DEFAULT` switch → **`nRF ONLY`**; PPK2 across `nRF meas` (P22)
- [ ] Marker-pin firmware support added (§4); pin = `P1.10` unless changed
- [ ] Supply voltage decided and written down (3.0 V suggested)
- [ ] `ENERGY-RESULTS-LOG.md` created

**Next action:** decide the marker pin, and I'll add the gated `ENERGY_MARKER_PIN`
support to `bench-stats.h` + `enroll-ops-bench` + the EDHOC bench so the energy and
latency windows are the same region by construction.
