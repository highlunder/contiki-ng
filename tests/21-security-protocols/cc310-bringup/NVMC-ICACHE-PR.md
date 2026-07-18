# Upstream PR: enable the nRF52840 NVMC instruction cache

> **Status: FUTURE WORK / deferred (lower priority).** The branch is prepared,
> rebased on current develop, and build-verified, but is **not** being pushed
> alongside the CC310 backend PR — it is an independent, optional optimization
> (it only affects software-crypto timing fairness, not the backend). Pick it
> up as a standalone PR later if/when desired. Kept local-only for now.

Minimal, self-contained change prepared as a clean branch off
`contiki-ng/contiki-ng` `develop`.

- **Branch:** `nrf52840-enable-icache` (registered in the local `contiki-ng` repo) — local-only, deferred
- **Base:** `origin/develop` (`contiki-ng/contiki-ng`) — rebased onto `f17a3f0ae` 2026-06-29 (clean); commit `6ab9ac339`
- **Diff:** 1 file, +11 lines — `arch/platform/nrf52840/platform.c`
- **Build:** verified clean for `nrf52840 BOARD=dk` (0 warnings).

This is isolated from all of our research work (C509, benches, CC310 backend):
it is *only* the platform-level cache enable, based on the pristine upstream
file, so the PR diff is exactly the eleven lines below.

## The change

In `platform_init_stage_one()`:

```c
/*
 * Enable the NVMC instruction cache.  The Cortex-M4 runs at 64 MHz while the
 * flash needs wait states at that clock, so without the I-cache every flash
 * fetch stalls the core.  Enabling it leaves correctness unchanged but roughly
 * halves the run time of flash-resident compute (e.g. software ECC); it is the
 * configuration Nordic's own SDK examples use.  It is left disabled out of
 * reset, so enable it as early as possible.
 */
NRF_NVMC->ICACHECNF =
  (NVMC_ICACHECNF_CACHEEN_Enabled << NVMC_ICACHECNF_CACHEEN_Pos);
```

## Suggested PR title

`arch/nrf52840: enable the NVMC instruction cache`

## Suggested PR body

> ### Contribution
> The nRF52840 Cortex-M4 runs at 64 MHz, a clock at which the on-chip flash
> needs wait states. The NVMC instruction cache is **disabled out of reset**,
> and Contiki-NG never enables it, so every flash fetch stalls the core on
> any cache-missing path.
>
> This enables the I-cache in `platform_init_stage_one()`. It does not change
> behaviour — it only removes flash-fetch stalls — and matches the
> configuration Nordic's own SDK examples ship with.
>
> ### Impact
> Flash-resident compute roughly halves in run time. The effect is most visible
> on software public-key crypto: in a secp256r1 micro-benchmark on an nRF52840-DK,
> per-operation cost dropped by ~2x with the cache enabled, bringing the numbers
> in line with the figures library authors report on zero-wait-flash reference
> boards (e.g. STM32F411 with the ART accelerator). Hardware-engine paths
> (CC310 CryptoCell) are largely unaffected, as expected.
>
> ### Testing
> Builds cleanly for `nrf52840 BOARD=dk`. Verified on hardware that ECC
> micro-benchmarks run correctly and ~2x faster with no other changes.

## How to push and open the PR

The commit lives on branch `nrf52840-enable-icache` in the local `contiki-ng`
repo. Push it to your GitHub fork of contiki-ng, then open the PR against
`contiki-ng/contiki-ng:develop`.

```sh
# one-time: add your fork as a remote (replace <you> with your GH user)
git -C contiki-ng remote add fork git@github.com:<you>/contiki-ng.git

# push the branch
git -C contiki-ng push -u fork nrf52840-enable-icache

# then open the PR (base: contiki-ng/contiki-ng develop), e.g. with gh:
gh pr create --repo contiki-ng/contiki-ng --base develop \
  --head <you>:nrf52840-enable-icache \
  --title "arch/nrf52840: enable the NVMC instruction cache" \
  --body-file contiki-ng/tests/21-security-protocols/cc310-bringup/NVMC-ICACHE-PR.md
```

## Notes

- The change is **not** applied to our fork branch (`c509-eval-phase5`); our
  benches enable the cache locally in-app (`ecc-bench.c` / `p256m-bench.c`) so
  their measurements are independent of this platform change. If you want the
  fork to also benefit platform-wide, cherry-pick `6ab9ac339` onto it (then the
  in-app enables become redundant but harmless).
- A scratch worktree was used to build the branch off pristine `develop`; it is
  ephemeral. The branch ref itself is safe in `contiki-ng/.git`.
- Possible reviewer ask: the newer `arch/cpu/nrf` (nrfx) tree used by other
  Nordic targets may want the same enable. This PR scopes to the `nrf52840`
  platform that `TARGET=nrf52840` builds; a follow-up can cover `arch/cpu/nrf`.
