# Vendored Monocypher (software X25519 + Ed25519)

Source: https://github.com/LoupVaillant/Monocypher
Upstream commit: `ab2b16dd619ad5f6979a4fbe69cfa324a6fcc35f`
License: CC0-1.0 / BSD-2-Clause (see LICENCE.md).

Portable, public-domain crypto. Used here as the **software** backend for the
X25519/Ed25519 micro-benchmark (`ec25519-bench-sw`), the counterpart to the
CC310 hardware `ec25519-bench`.

Files (unmodified):
- `monocypher.c` / `monocypher.h` — core, incl. `crypto_x25519*` (Curve25519 ECDH).
- `monocypher-ed25519.c` / `monocypher-ed25519.h` — optional module: standard
  RFC 8032 Ed25519 (curve25519 + **SHA-512**), `crypto_ed25519_{key_pair,sign,check}`.

Note: this is a clean reference software implementation chosen for being
self-contained (no mbedTLS dependency, unlike the in-tree `ed25519_verify.c`
which pulls `mbedtls/sha512.h`). It is a representative-software baseline for
the hardware-vs-software comparison; it is not the same code path as the EDHOC
handshake's Ed25519 (`ed25519_verify.c`), whose handshake-level timing is
reported separately in the paper.
