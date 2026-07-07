# nRF52840-DK bring-up ladder (software → CC310 crypto)

A step-wise sequence to gain confidence that the board, toolchain, flash path,
console, timing harness, and crypto (software **and** CryptoCell-310) all work,
**before** attempting the full networked EDHOC+OSCORE handshake. Each rung is
single-node, prints to the UART console, and needs **no network**.

Climb the rungs in order. Only move on when a rung passes — each one isolates a
different failure class, so a failure tells you exactly what's broken.

| Rung | App | Validates |
|------|-----|-----------|
| 0 | (toolchain) | WSL build + Windows flash path |
| 1 | `examples/hello-world` | boot, reach `main()`, UART console |
| 2 | `board-check` | clock/etimer + GPIO (LEDs) + uptime |
| 3 | `ecc-bench` | DWT cycle counter is alive |
| 4 | `ecc-bench` | ECC **correctness** (sign/verify, ECDH match) |
| 5 | `ecc-bench` (`ECC_HW_BACKEND=cc310`) | **CC310 accelerator** brings up + per-op cycles vs software |
| 6 | `edhoc-oscore-c5t-*` | full EDHOC+OSCORE handshake (needs a peer/network) |

---

## Setup (once)

- **Build host:** WSL, ARM toolchain at `/home/joel/toolchains/arm-gcc/bin/`.
- **Flash host:** Windows, **nRF Command Line Tools** (`nrfjprog`) installed.
- **Board:** nRF52840-DK on Windows **COM4**, J-Link serial **683609980**.
- **Console:** a serial terminal on Windows opening **COM4 @ 115200 8N1**
  (PuTTY, `nRF Connect: Serial Terminal`, or `python -m serial.tools.miniterm COM4 115200`).

### Build (WSL) — define the toolchain once

All builds use these tool overrides (the platform Makefile hard-codes the
assembler, so `AS=` is required):

```
TC=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi
make -C <appdir> TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= [ECC_HW_BACKEND=cc310] \
  CC=$TC-gcc AS=$TC-gcc LD=$TC-gcc AR=$TC-ar OBJCOPY=$TC-objcopy NM=$TC-nm
```

(Per the workspace shell rules, run it without the `$TC` shorthand — spell the
absolute paths out. The shorthand here is only for readability.)

### Produce a flashable HEX (WSL)

The Makefile's `.hex` target needs `srec_cat` (not installed). Generate Intel
HEX straight from the ELF with objcopy instead:

```
/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-objcopy -O ihex \
  <appdir>/build/nrf/nrf52840/dk/<app>.nrf \
  <appdir>/build/nrf/nrf52840/dk/<app>.hex
```

### Flash (Windows PowerShell)

The HEX lives under `\\wsl$\...` and is reachable from Windows. Flash with:

```
nrfjprog -f nrf52 --snr 683609980 --program <path>\<app>.hex --sectorerase --verify --reset
```

`nrfjprog --reset` (or pressing the board's RESET) restarts the firmware so you
see the boot output. `--snr 683609980` is optional if the DK is the only board.

> Note: the Contiki `make ... .upload` target won't work here — it calls
> `nrfjprog` from WSL, where it isn't installed. Flash from Windows instead.

---

## Rung 0 — toolchain + flash path

Goal: prove you can build a HEX in WSL and flash it from Windows at all. Just do
Rung 1 below; if the build produces a HEX and `nrfjprog` reports
`Verified OK` + `Applying reset`, Rung 0 passed.

## Rung 1 — hello-world (boot + console)

```
make -C ../../../examples/hello-world TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= <tool overrides>
objcopy -O ihex .../hello-world.nrf52840 .../hello-world.hex   # then flash
```

**Expect** on the console:

```
Hello, world
```

Pass = that line appears. Fail here ⇒ flash/console/baud problem (not your code).

## Rung 2 — board-check (clock + GPIO)

```
make -C board-check TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= <tool overrides>
```

**Expect:** a banner, then one line per second, and the LEDs visibly toggling:

```
=== nRF52840-DK board check ===
UART console OK if you can read this.
Expect one tick per second; LEDs toggle each tick.
uptime: 1 s
uptime: 2 s
...
```

Pass = uptime increments ~1/s **and** LEDs blink. Fail ⇒ clock or GPIO issue.

## Rungs 3–5 — ecc-bench (DWT + ECC correctness + cycles)

Same app, two backends. Build and flash the **software** build first, then the
**CC310** build, and compare.

**Software (uECC) — rungs 3 & 4:**
```
make -C ecc-bench TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= <tool overrides>
```

**CC310 hardware — rung 5:**
```
make -C ecc-bench TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= ECC_HW_BACKEND=cc310 <tool overrides>
```

**Expect** (per backend):

```
=== nRF52840 ECC benchmark (secp256r1) ===
backend: software (uECC)            # or "CC310 hardware"
DWT sanity: 1 ms delay measured ~64000 cyc (expect ~64000)     <- rung 3
--- iteration 1/5 ---
  keygen-A      NNNNNNNN cyc =   NN ms (  NNNNNN us)  res=0
  keygen-B      ...
  sign          ...                                    res=0
  verify        ...                                    res=0   <- res=0 means VALID
  ecdh-aB       ...                                    res=0
  ecdh-bA       ...                                    res=0
  ECDH shared secrets match (correctness OK)                   <- rung 4
... (5 iterations) ...
=== RESULT: PASS (software (uECC)) ===
```

Pass criteria:
- **Rung 3:** the "DWT sanity" line reads ~64000 cycles (64 MHz × 1 ms). If it
  reads 0 / implausible, the cycle counter isn't running (expected under
  emulation; on real silicon it must count).
- **Rung 4:** every `verify` line shows `res=0`, every iteration prints
  "shared secrets match", and the final line is `RESULT: PASS`. The **green**
  LED lights on PASS, **red** on FAIL.
- **Rung 5 (CC310):** same PASS, and the per-op cycle counts are **much lower**
  than the software build — that drop is the accelerator working. Sanity check:
  software `sign`+`verify`+`ecdh` ≈ the ~1172 ms figure in the paper
  (`table:bp256-arm-timing`); CC310 should be several× faster
  (cf. Fedrecheski 2024 ~135 ms full EDHOC handshake on CC310).

Record both runs' numbers in `cooja-ng/test-runs/TEST-LOG.md`.

## Rung 6 — full EDHOC+OSCORE c5t handshake (integration)

The end goal, and the only rung that needs a **peer + network** (border router /
second node, or Cooja). Build the existing client/server with profiling on:

```
make -C ../edhoc-oscore-c5t-client TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= \
     ECC_HW_BACKEND=cc310 EDHOC_PROFILE=1 <tool overrides>
make -C ../edhoc-oscore-c5t-server ...
```

The client prints `PROFILE ecc_sign: N cycles`, `PROFILE ecc_verify: …`,
`PROFILE ecc_generate_shared_secret: …`, and
`PROFILE handshake_wallclock: M ms` — the per-op and end-to-end numbers that
close the paper's `TODO-hw` markers. (Add the Power-Profiler-Kit GPIO marker
when you're ready to measure energy.)

---

### Why this order

Each rung removes one variable: Rung 1 proves the flash/console chain so a later
silence isn't a flashing problem; Rung 2 proves timers/GPIO so a hung benchmark
isn't a clock problem; Rung 3 proves the cycle counter so the numbers in Rungs
4–6 are trustworthy; Rung 4 proves the crypto is *correct* before you trust its
*speed*; Rung 5 isolates "does CC310 even run" from the full networked handshake
in Rung 6.
