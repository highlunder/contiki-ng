# Plan: migrate our nRF work from the deprecated `nrf52840` platform to the shared `nrf` platform

**Status:** investigation + plan only (2026-07-07). No migration performed.
**SECURITY NOTICE: Test credentials only. Never use in production.**

## Target change
| | Old (deprecated) | New (shared) |
|---|---|---|
| Build invocation | `TARGET=nrf52840 BOARD=dk` / `BOARD=dongle` | `TARGET=nrf BOARD=nrf52840/dk` / `nrf52840/dongle` |
| Platform dir | `arch/platform/nrf52840/` | `arch/platform/nrf/` (also hosts `nrf5340/`) |
| CPU dir | `arch/cpu/nrf52840/` (nRF5-**SDK** based, `lib/nrf52-sdk`) | `arch/cpu/nrf/` (**nrfx** based, `lib/nrfx`) |
| Output | `build/nrf52840/dk/<app>.nrf52840` | `build/nrf/nrf52840/dk/<app>.nrf` |
| Board conf/def | `contiki-conf.h`, `nrf52840-conf.h` | `BOARD_CONF_PATH=nrf52840-dk-conf.h`, `CPU_CONF_PATH=nrf52840-conf.h`, `CPU_DEF_PATH=nrf52840-def.h` |

**Verified this session:** stock shared platform builds+links in our tree
(`make TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR=`); the `LDFLAGS_WERROR=` is required to
survive the nrfx-MDK "LOAD segment with RWX permissions" linker warning (same as the nrf5340
note in `reference_nrf5340_dtls_blocker`). Output extension is `.nrf`, build dir `build/nrf/...`.

## Good news that shrinks the blast radius
- **`RTIMER_ARCH_SECOND = 62500` in both** (`nrf-def.h` and old `nrf52840-def.h`) — no rtimer/TSCH
  timing shift; the emulator's timing model is unaffected by that constant.
- **`NRF52840_XXAA` is defined by the shared platform too** (`arch/cpu/nrf/Makefile.nrf52840`).
  It is the *only* nRF platform macro our code keys on, in exactly **one** file
  (`examples/lwm2m-ipso-objects/project-conf-dtls.h`) — so it keeps working. We use **no**
  `CONTIKI_TARGET_NRF52840` `#ifdef`s in our services/apps. **Source-macro impact ≈ zero.**
- Board conf/def filenames (`nrf52840-conf.h`, `nrf52840-def.h`) exist in the shared tree, so our
  small conf additions merge in place.

## The real porting surface — our 11 customised files in the old tree
(from commits `0767004d4..HEAD`: CC310 backend, Renode/emulator clock+CCA fixes, mbedTLS heap
linker, build hooks). Mapping to the reorganised shared tree:

| Old file (our change) | New shared location | Risk | Notes |
|---|---|---|---|
| `dev/nrf52840-cc310-ecc.c` (NEW, 516 L) | `arch/cpu/nrf/dev/` | **HIGH** | CC310 ECC `lib/ecc.h` backend |
| `Makefile.cc310-crypto` (NEW, 149 L) | `arch/cpu/nrf/` + hook `Makefile.nrf52840` | **HIGH** | pulls `lib/nrf52-sdk` crypto + CC310 blob |
| `Makefile.nrf52840` (+5, cc310 hook) | `arch/cpu/nrf/Makefile.nrf52840` | **HIGH** | re-hook `ECC_HW_BACKEND=cc310` |
| `ld/nrf_common.ld` (NEW, 195 L, heap) | override `LDSCRIPT` or patch nrfx `nrf52840_xxaa.ld` | MED | mbedTLS heap arena size |
| `clock.c` (+41, "Renode" fix) | `sys/clock-arch.c` | MED | re-evaluate vs nrfx clock; may be unneeded |
| `rf/nrf52840-ieee.c` (+46, CCA fix) | `net/nrf-ieee-driver-arch.c` | MED | re-apply CCA/Renode fix if still needed |
| `dev/uart0.c` (+8) | `dev/uarte-arch.c` | MED | different (nrfx UARTE) API |
| `arch/platform/nrf52840/platform.c` (+25) | `arch/platform/nrf/platform.c` | MED | platform init changes |
| `nrf52840-conf.h` (+8) | `arch/cpu/nrf/nrf52840-conf.h` | LOW | merge |
| `dbg.c` (+17) | `os/dbg-arch.c` | LOW | |
| `dev/watchdog.c` (+3) | `dev/watchdog-arch.c` | LOW | |

## THE blocker: CC310 hardware-crypto backend
`Makefile.cc310-crypto` + `nrf52840-cc310-ecc.c` depend on **`lib/nrf52-sdk/`** (Nordic nRF5 SDK
subset: `nrf_crypto_*` frontend, `cc310_backend_*`, `mem_manager`, `nrf_atomic`) **plus the
closed-source `libnrf_cc310_0.9.13.a` blob**. The shared CPU tree (`arch/cpu/nrf/lib/`) contains
**only `nrfx` and `tinyusb`** — **no `nrf52-sdk`, no CC310 lib.** So porting CC310 is not a file
move; it needs a strategy decision (own spike):
- **Option A — vendor the nrf52-sdk subset under `arch/cpu/nrf/lib/nrf52-sdk`** and gate it on
  `ECC_HW_BACKEND=cc310`. Risk: the nRF5-SDK HAL/CMSIS headers can collide with nrfx (both define
  `nrf.h`/`NRF_*`/startup); needs include-order isolation and possibly `nrfx_glue` shims. This is
  the lowest-behaviour-change path but the coexistence must be proven.
- **Option B — re-target CC310 through nrfx/CryptoCell** (nrfx `nrf_cc310`/CRACEN or the
  `nrf_oberon` lib) instead of the SDK frontend. Cleaner long-term, but a real rewrite of the
  516-line backend and its RNG/mutex glue.
- Recommendation: **spike Option A first** (least logic change, keeps the validated CC310 numbers);
  fall back to B if nrf52-sdk↔nrfx coexistence proves intractable. Either way the closed
  `libnrf_cc310` blob path (`NRF_CC310_SDK`) must be re-pointed.

## Emulator (cooja-ng-ge) workstream — do NOT overlook
The emulator selects the SoC by firmware **extension** (`src/sim/sim_board.c`): it knows
`.nrf52840`, `.nrf52840-dk`, `.nrf52840-dongle`, `.nrf54l15-dk` — but **not `.nrf`**, which the
shared build now emits and which is ambiguous (nrf52840 vs nrf5340). Two sub-tasks:
1. **Artifact naming.** Cheapest: have our build scripts copy `…/<app>.nrf` →
   `<app>.nrf52840-dk` (extension the registry already maps). Alternative: add a `.nrf` row to
   `sim_board.c` defaulting to nrf52840-dk, plus explicit `.nrf5340*` rows — but `.nrf` alone
   cannot distinguish SoCs, so prefer board-specific renames.
2. **SoC-model fidelity (the real validation gate).** `nrf52840_soc.c` was validated against the
   **old SDK** firmware. The nrfx drivers may drive different peripheral instances/registers
   (clock source, RTC/TIMER for the system clock + rtimer, UARTE config, RADIO setup). The
   emulator models the hardware, so standard peripheral use should "just work" — but this MUST be
   confirmed by building a shared-platform netstack image and running it in the emulator
   (boot → TSCH assoc → the rxdiag all-nRF baseline). Any divergence = targeted `nrf52840_soc.c`
   fixes. Treat this as the migration's acceptance test on the emulator side.
3. **Config/path churn.** Every emulator JSON + script references `build/nrf52840/dk/*.nrf52840`;
   these become `build/nrf/nrf52840/dk/*.nrf` (or the renamed artifact).

## Build-script / config churn (mechanical, wide)
~24 files reference `TARGET=nrf52840` across `local-tests/` (bench, rxdiag, tsch-*, edhoc rungs,
build-all), `tests/21-security-protocols/` (cc310-bringup, bignum), and `examples/`. Each needs:
`TARGET=nrf52840 BOARD=dk` → `TARGET=nrf BOARD=nrf52840/dk`, add `LDFLAGS_WERROR=`, and fix output
paths/extensions (`build/nrf52840/dk/…nrf52840` → `build/nrf/nrf52840/dk/…nrf` or renamed). The
rxdiag `project-conf.h` `#if defined(CONTIKI_TARGET_ZOUL)||defined(CONTIKI_TARGET_CC2538DK)` branch
is unaffected (nRF falls to the `#else`, macro-name independent).

## Phased execution (each phase gated, warning-free)
1. **Baseline & board bring-up.** Build hello-world + a netstack example on `TARGET=nrf
   BOARD=nrf52840/dk LDFLAGS_WERROR=`; flash-run on HW (if available) and run in the emulator
   (rename artifact). Confirms the stock shared platform is good in our tree end-to-end. *(hello
   build already verified.)*
2. **Emulator support.** Artifact-naming shim + `sim_board.c` if needed; run the **all-nRF rxdiag
   TSCH baseline** on shared-platform leaf/root firmware — the acceptance test for SoC-model
   fidelity. Fix `nrf52840_soc.c` only if it diverges.
3. **Low-risk arch ports.** dbg, watchdog, conf, platform.c, uart→uarte, heap linker override.
   Re-evaluate the Renode clock + radio-CCA fixes against the nrfx `clock-arch.c`/
   `nrf-ieee-driver-arch.c` — port only if still needed. Rebuild the DTLS/EDHOC (sw-crypto)
   apps; re-run native+emulator handshake tests.
4. **CC310 spike (highest risk, isolate).** Prove nrf52-sdk↔nrfx coexistence (Option A) with a
   minimal ecc-bench, then port the full backend + re-point the blob; re-run the on-HW CC310
   ecc/ecdh/compress validation + the 3-way P-256 bench. Fall back to Option B if blocked.
5. **Sweep the build scripts/configs** (~24) + docs to the new target/paths; keep a thin
   compatibility note. Optionally keep old target working during transition (dual-target) until
   parity is proven, then remove.
6. **Full regression** across categories (matrix below); update memory + CLAUDE.md build commands.

## Verification matrix
- sw-crypto DTLS/EDHOC handshake: native + emulator + HW.
- CC310 hw-crypto: on-HW ecc/ecdh/compress + P-256 bench parity vs the recorded numbers.
- TSCH: all-nRF rxdiag baseline (emulator) + a HW join.
- Bench suite (`local-tests/bench`): builds + emulator runs.
- No new compiler/linker warnings (beyond the known nrfx RWX one handled by `LDFLAGS_WERROR=`).

## Decisions (2026-07-07)
1. **Full switch, no dual-target.** Urgency: upstream is landing new fixes *only* on the shared
   `nrf` platform, so we migrate fully and retire the old-target build paths (no compatibility
   shim kept once parity is proven).
2. **CC310 = Option A** (vendor the `nrf52-sdk` crypto subset + blob alongside nrfx, gated on
   `ECC_HW_BACKEND=cc310`); fall back to Option B (rewrite on nrfx/Oberon) only if the SDK↔nrfx
   coexistence proves intractable.
3. **nrf52840-only for now; defer nrf5340** (more nRF52840 HW is now available; the nrf5340 work
   stays parked per `reference_nrf5340_dtls_blocker`).
