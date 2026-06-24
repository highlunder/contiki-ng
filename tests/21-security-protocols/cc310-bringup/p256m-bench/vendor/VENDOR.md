# Vendored p256-m (standalone)

`p256-m-sa.c` / `p256-m.h` are a **self-contained** copy of p256-m (Manuel
Pégourié-Gonnard's compact, constant-time P-256 software implementation),
derived from the in-tree mbedTLS 3rdparty copy at
`os/net/security/mbedtls/3rdparty/p256-m/p256-m/`.

The in-tree copy is coupled to mbedTLS/PSA (the implementation is gated behind
`MBEDTLS_PSA_P256M_DRIVER_ENABLED`, includes `mbedtls/platform_util.h` and
`psa/crypto.h`, and supplies its RNG via `psa_generate_random`), so it cannot be
built standalone. `p256-m-sa.c` removes that coupling with four edits:

1. drop the `mbedtls/platform_util.h` and `psa/crypto.h` includes;
2. remove the outer `#if defined(MBEDTLS_PSA_P256M_DRIVER_ENABLED)` / `#endif`
   gate (the impl always compiles);
3. replace `#define zeroize mbedtls_platform_zeroize` with a local constant-time
   `zeroize()`;
4. remove the PSA-based `p256_generate_random` wrapper, so the
   integrator-supplied `p256_generate_random` (in `p256m-bench.c`, fed from the
   Contiki RNG, benchmark-grade) is used.

The P-256 arithmetic is byte-for-byte the upstream code. Host-validated:
keygen/sign/verify rc=0, tampered-sig rejected, ECDH symmetric.

License: Apache-2.0 (as upstream p256-m).
