# Upstream PR: nRF52840 CryptoCell-310 (CC310) hardware ECC backend

The **Contiki integration** for the CC310 hardware-crypto backend, extracted as a
clean branch off `contiki-ng/contiki-ng` `develop`. The closed-source CryptoCell
binary blob and CRYS/SaSi headers are **referenced** from a full nRF5 SDK install,
not vendored — that is the "minimal" part.

- **Status:** ✅ **PUSHED 2026-06-29** to fork `highlunder/contiki-ng` (remote `highunder-contiki`), branch `nrf52840-cc310-ecc-backend`, at `af6a69c60`/`809eb01c7` (style-clean, rebased on current develop, hardware-validated). Force-with-lease was used to replace the earlier pre-format push.
- **Branch:** `nrf52840-cc310-ecc-backend` (registered in the local `contiki-ng` repo)
- **Base:** `origin/develop` (`contiki-ng/contiki-ng`) — rebased onto `f17a3f0ae` 2026-06-29 (clean, no conflicts; zero file overlap with upstream changes)
- **Style:** verified with the repo's own `tools/code-style/uncrustify-check-style.sh`; only residual diff is the known `PT_THREAD(...)` pointer-spacing false positive, identical to the in-tree `cc2538-ecc.c` precedent. Full BSD header + `\author` + `\file` Doxygen in place.
- **Diff:** 11 files, +1000/−3, two commits:
  - `af6a69c60` — the CC310 backend (7 files).
  - `809eb01c7` — `examples/libs/ecc` enablement: build on embedded targets +
    selectable HW acceleration + `ecc_session_begin/end` wrap (4 files).
- **Build:** verified clean (0 warnings) against pristine `develop` for native
  (software), `nrf52840/dk` software, and `nrf52840/dk` CC310; native `ecdsa`
  runs keygen/validate/sign/verify to completion.

## Hardware verification (the in-tree test)

`examples/libs/ecc` is now the on-device test. The three programs drive the
`lib/ecc.h` service the backend implements and print which backend ran plus
per-op timings; `ecdsa` covers keygen/validate/sign/verify, `ecdh` covers ECDH,
`compress` covers point decompress. They wrap the ops in
`ecc_session_begin()/ecc_session_end()` (no-ops in software; on CC310 these do
the power-hold + one-time TRNG instantiation that keygen/sign need), so the same
source runs with or without acceleration — chosen at build time:

```sh
# software (uECC) — default, any target
make -C examples/libs/ecc TARGET=nrf52840 BOARD=dk

# CC310 hardware
make -C examples/libs/ecc TARGET=nrf52840 BOARD=dk \
     ECC_HW_BACKEND=cc310 NRF_CC310_SDK=/path/to/nRF5_SDK_17.1.0_ddde560
```

Flash `ecdsa.nrf52840` (CC310) and read the UART: a clean run prints
`ECC backend: CC310 hardware` followed by four `... took Nms` lines and no
`... failed` — that is the backend verified on silicon. Pre-built CC310 hexes
for a quick flash are staged at
`tests/21-security-protocols/cc310-bringup/hex/ecc-example-{ecdsa,ecdh}-cc310.hex`
(gitignored; rebuild with the make line above).

## What's in it (and deliberately not)

**Included** (the backend + its required glue):
- `arch/cpu/nrf52840/dev/nrf52840-cc310-ecc.c` — the `lib/ecc.h` backend on CC310.
- `arch/cpu/nrf52840/Makefile.cc310-crypto` — build wiring (sources, include paths,
  feature flags, blob reference, linker `-L`).
- `arch/cpu/nrf52840/Makefile.nrf52840` — includes the above when `ECC_HW_BACKEND=cc310`.
- `arch/cpu/nrf52840/ld/nrf_common.ld` — patched linker script adding the
  `.crypto_data` section (so the submodule stays pristine).
- `os/services/ecc/Makefile.ecc` — excludes the software `ecc.c` for the CC310 build
  (keeps micro-ecc linked for `uECC_decompress`).
- `os/lib/ecc.h` + `os/services/ecc/ecc.c` — new `ecc_session_begin()/ecc_session_end()`
  API (no-ops in software; CC310 uses them for power-gating + the one-time
  BASEPRI-isolated TRNG instantiation).

**Excluded** (separate concerns, intentionally kept out of a minimal backend PR):
- EDHOC cycle-profiling (`edhoc-profile.h`, `edhoc/ecdh.c` hooks, c5t-client) —
  instrumentation, and depends on the fork's EDHOC stack.
- The `cc310-bringup/` test-app ladder (ecc-bench, ec25519-bench, mlkem-bench,
  vendored monocypher/mlkem) — our measurement scaffolding.
- `dbg.c` RTT routing, `uart0.c` TX busy-wait, `nrf52840-conf.h` radio-override
  guard, and the uECC brainpoolP256r1 hunk — bring-up/bench tweaks, each
  independently justifiable as its own change if desired.

## How the blob is referenced (not vendored)

`Makefile.cc310-crypto`:
```make
# Full nRF5 SDK 17.1.0 root — provides the CC310 blob + CRYS/SaSi headers.
NRF_CC310_SDK ?= $(CONTIKI)/../nRF5_SDK_17.1.0_ddde560
CC310_BLOB := $(NRF_CC310_SDK)/external/nrf_cc310/lib/cortex-m4/hard-float/libnrf_cc310_0.9.13.a
ifeq (,$(wildcard $(CC310_BLOB)))
  $(error CC310 blob not found at $(CC310_BLOB) -- set NRF_CC310_SDK to your nRF5 SDK 17.1.0 root)
endif
...
TARGET_LIBFILES += $(CC310_BLOB)
CFLAGS += -I$(NRF_CC310_SDK)/external/nrf_cc310/include
```
The `nrf_crypto` frontend + cc310 backend `.c` come from the **in-tree**
`arch/cpu/nrf52840/lib/nrf52-sdk` submodule (the submodule pointer is identical to
upstream's, so they are already present; the submodule is untouched).

## Build / test

```sh
# default software build (regression — unchanged behaviour)
make -C examples/libs/ecc TARGET=nrf52840 BOARD=dk

# CC310 hardware backend (needs the full nRF5 SDK 17.1.0)
make -C examples/libs/ecc TARGET=nrf52840 BOARD=dk \
     ECC_HW_BACKEND=cc310 NRF_CC310_SDK=/path/to/nRF5_SDK_17.1.0_ddde560
```
(Upstream `examples/libs/ecc` was native-only; the second commit makes it pull the
ECC service on all targets and adds the `ECC_HW_BACKEND` switch, so the nRF build
above works as-is — no temporary edits needed.)

## Suggested PR title

`nrf52840: CryptoCell-310 (CC310) hardware ECC backend for lib/ecc.h`

## Suggested PR body

> ### Contribution
> An opt-in nRF52840 CryptoCell-310 backend for the `lib/ecc.h` ECC service,
> mirroring the existing `cc2538-ecc.c` precedent. Enabled with
> `ECC_HW_BACKEND=cc310`; default builds are unchanged. secp256r1 by default,
> Curve25519/Ed25519 behind `CC310_ECC_25519=1`.
>
> The Nordic `nrf_crypto` frontend + cc310 backend sources come from the in-tree
> `nrf52-sdk` submodule. The closed CryptoCell runtime blob and CRYS headers are
> **referenced** from a full nRF5 SDK 17.1.0 (via `NRF_CC310_SDK`), not vendored —
> the build emits a clear error if the SDK isn't found. A patched `nrf_common.ld`
> (shipped in `arch/cpu/nrf52840/ld/`, used only for CC310 builds) supplies the
> `crypto_data` linker section `nrf_crypto_init()` walks, leaving the submodule
> pristine.
>
> Adds a small `ecc_session_begin()/ecc_session_end()` ECC-service API so a caller
> can hold accelerator power and do the one-time CC310 TRNG instantiation across a
> whole handshake; both are no-ops on the software backend.
>
> ### Testing
> Builds cleanly (0 warnings) for `nrf52840/dk` in both the CC310 and default
> software configurations. Validated on real nRF52840-DK hardware: secp256r1
> keygen/sign/verify/ECDH run correctly on CC310, ~19 ms/op.
>
> ### Note for reviewers
> The blob is licensed under Nordic's 5-clause SLA and so cannot be redistributed
> in-tree — hence the reference-by-path approach. The `INTERRUPTS_ENABLED=1` /
> BASEPRI-isolated TRNG instantiation is required: the blob's TRNG wait depends on
> the CRYPTOCELL NVIC interrupt, and entropy collection must be isolated from the
> RTC tick (confirmed on hardware).

## How to push and open the PR

```sh
git -C contiki-ng remote add fork git@github.com:<you>/contiki-ng.git   # one-time
git -C contiki-ng push -u fork nrf52840-cc310-ecc-backend
gh pr create --repo contiki-ng/contiki-ng --base develop \
  --head <you>:nrf52840-cc310-ecc-backend \
  --title "nrf52840: CryptoCell-310 (CC310) hardware ECC backend for lib/ecc.h" \
  --body-file contiki-ng/tests/21-security-protocols/cc310-bringup/CC310-BACKEND-PR.md
```

## Notes

- The commit lives on branch `nrf52840-cc310-ecc-backend` in `contiki-ng/.git`
  (a scratch worktree off `develop` was used to build it; the worktree is
  ephemeral, the branch ref is not).
- Follow-ups a reviewer might want, deferrable to separate PRs: the same backend
  for the newer `arch/cpu/nrf` (nrfx) tree; the Path-1 mbedTLS `_ALT` route for
  DTLS; upstreaming the in-app energy/cycle profiling once EDHOC lands.
- Separate, independent change: `nrf52840-enable-icache` branch (NVMC instruction
  cache) — see `NVMC-ICACHE-PR.md`. Worth landing alongside, as it roughly halves
  software-crypto run time and makes the hw-vs-sw comparison fair.
