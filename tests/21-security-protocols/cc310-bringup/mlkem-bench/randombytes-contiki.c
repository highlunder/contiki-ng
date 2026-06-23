/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * randombytes() backend for the vendored ML-KEM reference (which calls
 * randombytes() for keygen/encaps coins).  Backed by Contiki's OFB-AES-128
 * CSPRNG, seeded once from the platform PRNG.
 *
 * NOTE: benchmark-grade.  The seed comes from random_rand(), which is fine for
 * timing and for the enc/dec self-test (decapsulation is deterministic given
 * the ciphertext), but a deployment must seed the CSPRNG from a real entropy
 * source (e.g. the CC310 TRNG via nrf_crypto_rng).
 */

#include "mlkem/randombytes.h"
#include "lib/csprng.h"
#include "lib/random.h"
#include <stddef.h>
#include <stdint.h>

static bool seeded;

void
randombytes(uint8_t *out, size_t outlen)
{
  if(!seeded) {
    struct csprng_seed seed;
    size_t i;
    for(i = 0; i < CSPRNG_SEED_LEN; i++) {
      seed.u8[i] = (uint8_t)random_rand();
    }
    csprng_feed(&seed);
    seeded = true;
  }
  csprng_rand(out, outlen);
}
