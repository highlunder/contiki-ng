# Vendored ML-KEM (FIPS 203) reference implementation

Source: https://github.com/pq-crystals/kyber (the `ref/` portable-C tree)
Upstream commit: `4768bd37c02f9c40a46cb49d4d1f4d5e612bb882`
License: CC0 / public domain or Apache-2.0 (see LICENSE).

This is the **reference** implementation — portable, correct, FIPS 203-aligned
(it exposes the derandomized `*_keypair_derand` / `*_enc_derand` APIs and the
ML-KEM byte sizes). It is **not** Cortex-M optimized; the optimized path for
nRF52840 is pqm4 / mlkem-native (NTT + Keccak in ARM assembly), which is the
natural follow-up once the reference numbers establish the baseline. CC310 does
**not** accelerate ML-KEM (no lattice/Keccak primitives), so unlike ECC there
is no hardware column here — only software.

## Local changes
- `randombytes.c` (OS-specific entropy) was **dropped**; the benchmark provides
  its own `randombytes()` in `../randombytes-contiki.c`, backed by Contiki's
  CSPRNG (seeded from the platform PRNG — benchmark-grade, not production).
- Test/KAT harness dirs (`test/`, `nistkat/`) and the upstream `Makefile` were
  not copied.

## Security level
Selected at build time via `KYBER_K` (params.h): 2 = ML-KEM-512, 3 = ML-KEM-768
(default), 4 = ML-KEM-1024. The bench Makefile maps `MLKEM=512|768|1024`.
