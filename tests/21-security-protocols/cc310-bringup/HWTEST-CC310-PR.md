# Local hardware test — CC310 ECC backend PR branch

Step-by-step for checking out the `nrf52840-cc310-ecc-backend` PR branch and
verifying the CryptoCell-310 ECC backend on a real nRF52840-DK.

The PR branch is based on upstream `develop`, so it does **not** contain the
`c509-eval-phase5` stack (this `cc310-bringup/` dir, EDHOC, C509…). The on-device
test on that branch is `examples/libs/ecc` itself. Use a **git worktree** so the
current `c509-eval-phase5` checkout is left untouched.

Build in WSL (arm-gcc 13.2), flash from Windows (`nrfjprog`, J-Link SN
**683609980**). See `../../../../` repo root and `[[reference_arm_toolchain]]`
notes for toolchain details.

## 1. Check out the PR branch into an isolated worktree (WSL)

```sh
git -C /home/joel/gemini_workspace/contiki-ng worktree add \
  /home/joel/gemini_workspace/cc310-pr-test nrf52840-cc310-ecc-backend
```

Only the closed CryptoCell **blob + CRYS headers** are referenced externally via
`NRF_CC310_SDK` (`/home/joel/gemini_workspace/nRF5_SDK_17.1.0_ddde560`).

**If `worktree add` fails with `'...' is already checked out at <scratch path>`:**
a leftover worktree from a previous session is pinning the branch. Release it,
then re-run the add:
```sh
git -C /home/joel/gemini_workspace/contiki-ng worktree list           # find the stale path
git -C /home/joel/gemini_workspace/contiki-ng worktree remove --force <stale path>
```

**A fresh worktree does NOT populate submodules** — the `nrf_crypto` frontend +
cc310 backend `.c` live in the `nrf52-sdk` submodule, so init it in the worktree
before building (one-time):
```sh
git -C /home/joel/gemini_workspace/cc310-pr-test submodule update --init \
  arch/cpu/nrf52840/lib/nrf52-sdk
```

## 2. Build the CC310 hardware variant (WSL, arm-gcc 13.2)

The toolchain must be passed explicitly (Makefile.include's `AS` is clang-only;
the `.S` startup file needs `AS=` too):

```sh
make -C /home/joel/gemini_workspace/cc310-pr-test/examples/libs/ecc \
  TARGET=nrf52840 BOARD=dk \
  ECC_HW_BACKEND=cc310 \
  NRF_CC310_SDK=/home/joel/gemini_workspace/nRF5_SDK_17.1.0_ddde560 \
  CC=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc \
  AS=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc \
  LD=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc \
  AR=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-ar \
  OBJCOPY=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-objcopy \
  NM=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-nm
```

Expect 0 warnings and a clean link (the `Makefile.cc310-crypto` guard errors out
immediately if the blob path is wrong). Convert the ELF to Intel-hex (no
`srec_cat` in this environment, so call objcopy directly):

```sh
/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-objcopy -O ihex \
  /home/joel/gemini_workspace/cc310-pr-test/examples/libs/ecc/build/nrf52840/dk/ecdsa.nrf52840 \
  /home/joel/gemini_workspace/cc310-pr-test/ecdsa-cc310.hex
```

(Repeat for `ecdh.nrf52840` → `ecdh-cc310.hex` for the ECDH path; `compress`
covers point decompress.)

## 3. Flash from Windows (nrfjprog, J-Link SN 683609980)

From a Windows shell (the `\\wsl$` share reaches the file):

```bat
nrfjprog --snr 683609980 -f nrf52 --program ecdsa-cc310.hex --sectorerase --verify
nrfjprog --snr 683609980 -f nrf52 --reset
```

Or drop the freshly built `.hex` next to `hex/flash.bat` (which hard-codes that
SN) and run `flash.bat ecdsa-cc310.hex`.

## 4. Read UART and judge PASS

Open the serial console (was COM4/COM5 with the SEGGER driver), 115200 8N1:

```bat
plink -serial COM5 -sercfg 115200,8,n,1,N
```

A healthy CC310 run prints:
- `ECC backend: CC310 hardware`
- four `... took Nms` lines (keygen/validate/sign/verify), each ~**19 ms**
- **no** `... failed` line

That sequence = backend verified on silicon. If TRNG seeding regresses you'd see
a failure instead — the fix (BASEPRI-isolated TRNG instantiation against the
128 Hz RTC tick) lives in `ecc_session_begin()`; see the CC310 RNG IRQ notes.

## 5. Software regression baseline (same source, recommended)

Confirms the PR doesn't disturb the default path — same command, drop the two
CC310 vars:

```sh
make -C /home/joel/gemini_workspace/cc310-pr-test/examples/libs/ecc \
  TARGET=nrf52840 BOARD=dk \
  CC=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc \
  AS=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc \
  LD=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-gcc \
  AR=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-ar \
  OBJCOPY=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-objcopy \
  NM=/home/joel/toolchains/arm-gcc/bin/arm-none-eabi-nm
```

Prints `ECC backend: software (uECC)` instead, with ~150–180 ms/op software
timings.

## 6. Clean up the worktree when done

```sh
git -C /home/joel/gemini_workspace/contiki-ng worktree remove \
  /home/joel/gemini_workspace/cc310-pr-test
```

## Notes

- The `examples/libs/ecc` on-device timings are **uninstrumented and not
  I-cache-tuned** — a backend-correctness test, not paper numbers. The stamped
  paper measurements stay the `cc310-bringup` benches on `c509-eval-phase5`
  (`BENCH-RESULTS-LOG.md`, fw `20260626`).
- The companion **`nrf52840-enable-icache`** branch (NVMC I-cache,
  `NVMC-ICACHE-PR.md`) is independent; landing it alongside is what makes the
  hw-vs-sw comparison fair (it ~halves software-crypto time). Test it the same
  way against any software build.
- Full PR context: `CC310-BACKEND-PR.md` (this dir).
