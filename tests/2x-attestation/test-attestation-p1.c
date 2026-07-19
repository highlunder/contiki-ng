/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   P1 tests for the RA-over-EDHOC attestation crypto core
 *   (os/services/attestation): the attestation binder (H_12 + HKDF from a real
 *   transcript) and the full Attester->Verifier Evidence flow (sign + appraise),
 *   the C analog of the Rust reference impl's Tier B (I, Background-check).
 *
 *   Standalone (host gcc) only: uses os/lib/sha-256 for the binder and Monocypher
 *   Ed25519 as the pluggable sign/verify backend. The on-device signer/verifier
 *   is a platform backend (uECC/CC310, or the nRF5340 TrustZone secure world).
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-attester.h"
#include "ra-verifier.h"
#include "ra-binder.h"
#include "ra-cose.h"
#include "lib/sha-256.h"
#include "monocypher-ed25519.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_pass, g_fail;
#define CHECK(cond, name) do {                                             \
    if(cond) { g_pass++; printf("  ok   %s\n", (name)); }                  \
    else     { g_fail++; printf("  FAIL %s\n", (name)); }                  \
  } while(0)

/* --- Monocypher-backed sign/verify adapters (the pluggable crypto backend). --- */
static void
mc_sign(void *ctx, const uint8_t *tbs, size_t tbslen, uint8_t sig[64])
{
  const uint8_t *sk = (const uint8_t *)ctx; /* 64-byte Ed25519 secret key */
  crypto_ed25519_sign(sig, sk, tbs, tbslen);
}
static int
mc_verify(void *ctx, const uint8_t *pubkey, const uint8_t *msg, size_t msglen,
          const uint8_t sig[64])
{
  (void)ctx;
  return crypto_ed25519_check(sig, pubkey, msg, msglen);
}

static const uint8_t ID_CRED_I[4] = { 0xA1, 0x04, 0x41, 0x2B }; /* {4: h'2b'} */

static void
firmware_measurement(uint8_t out[34])
{
  out[0] = 0x58; out[1] = 0x20; /* CBOR bstr(32) */
  memset(out + 2, 0xAB, 32);
}

/* HKDF-Expand RFC 5869 Test Case 1 (SHA-256), proving os/lib usage is correct. */
static void
hexbytes(const char *hex, uint8_t *out, size_t n)
{
  for(size_t i = 0; i < n; i++) {
    unsigned v;
    sscanf(hex + 2 * i, "%2x", &v);
    out[i] = (uint8_t)v;
  }
}

static void
kat_hkdf_rfc5869(void)
{
  uint8_t prk[32], info[10], okm[42], expected[42];
  hexbytes("077709362c2e32df0ddc3f0dc47bba63"
           "90b6c73bb50f9c3122ec844ad7c2b3e5", prk, 32);
  hexbytes("f0f1f2f3f4f5f6f7f8f9", info, 10);
  hexbytes("3cb25f25faacd57a90434f64d0362f2a"
           "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
           "34007208d5b887185865", expected, 42);
  sha_256_hkdf_expand(prk, 32, info, 10, okm, 42);
  CHECK(memcmp(okm, expected, 42) == 0, "HKDF-Expand-SHA256 == RFC 5869 TC1 OKM");
}

static void
kat_binder(void)
{
  const uint8_t m1[4] = { 0x03, 0x01, 0x02, 0x03 };
  const uint8_t m2[3] = { 0x04, 0x05, 0x06 };
  uint8_t b1[32], b2[32], bx[32];

  CHECK(ra_binder_m3(b1, m1, sizeof(m1), m2, sizeof(m2), ID_CRED_I, 4) == 0, "binder_m3 computes");
  ra_binder_m3(b2, m1, sizeof(m1), m2, sizeof(m2), ID_CRED_I, 4);
  CHECK(memcmp(b1, b2, 32) == 0, "binder_m3 deterministic");

  /* Anti-relay sensitivity: any transcript/identity change alters the binder. */
  const uint8_t m1b[2] = { 0x03, 0x09 };
  ra_binder_m3(bx, m1b, sizeof(m1b), m2, sizeof(m2), ID_CRED_I, 4);
  CHECK(memcmp(bx, b1, 32) != 0, "binder_m3 changes with message_1");
  const uint8_t m2b[2] = { 0x04, 0x09 };
  ra_binder_m3(bx, m1, sizeof(m1), m2b, sizeof(m2b), ID_CRED_I, 4);
  CHECK(memcmp(bx, b1, 32) != 0, "binder_m3 changes with message_2");
  const uint8_t idb[4] = { 0xA1, 0x04, 0x41, 0x2C };
  ra_binder_m3(bx, m1, sizeof(m1), m2, sizeof(m2), idb, 4);
  CHECK(memcmp(bx, b1, 32) != 0, "binder_m3 changes with ID_CRED_I");
}

static void
kat_evidence_flow(void)
{
  /* Synthetic EDHOC transcript + attestation keypair. */
  uint8_t seed[32], sk[64], pk[32];
  for(int i = 0; i < 32; i++) { seed[i] = (uint8_t)(i + 1); }
  crypto_ed25519_key_pair(sk, pk, seed); /* wipes seed */

  const uint8_t msg1[16] = { 0x03,0x58,0x20,0x11,0x22,0x33,0x44,0x55,
                             0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD };
  const uint8_t msg2[20] = { 0x58,0x28,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                             0x09,0x0A,0x0B,0x0C,0x0D,0x0E,0x0F,0x10,0x11,0x12 };
  const uint8_t nonce[8] = { 0xA2,0x9F,0x62,0xA4,0xC6,0xCD,0xAA,0xE5 };
  const uint8_t *ueid = (const uint8_t *)"device01";
  uint8_t meas[34];
  firmware_measurement(meas);

  uint8_t evidence[512];
  size_t evlen;
  int built = ra_attester_build_evidence(evidence, sizeof(evidence), &evlen,
                                         ra_cose_protected_eddsa, 3,
                                         nonce, sizeof(nonce), ueid, 8,
                                         258, meas, sizeof(meas),
                                         msg1, sizeof(msg1), msg2, sizeof(msg2),
                                         ID_CRED_I, 4, mc_sign, sk);
  CHECK(built == 0, "Attester builds signed Evidence");

  /* Relying Party appraisal (fresh nonce + transcript-bound signature + reference). */
  ra_appraise_result_t r =
    ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                         msg1, sizeof(msg1), msg2, sizeof(msg2), ID_CRED_I, 4,
                         pk, meas, sizeof(meas), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_PASS, "Verifier appraisal PASS");

  /* Negatives: each failure mode is distinguished. */
  const uint8_t bad_nonce[8] = { 0 };
  r = ra_verifier_appraise(evidence, evlen, bad_nonce, sizeof(bad_nonce),
                           msg1, sizeof(msg1), msg2, sizeof(msg2), ID_CRED_I, 4,
                           pk, meas, sizeof(meas), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_NONCE_MISMATCH, "wrong nonce -> NONCE_MISMATCH");

  const uint8_t bad_m1[3] = { 0x03, 0xDE, 0xAD };
  r = ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                           bad_m1, sizeof(bad_m1), msg2, sizeof(msg2), ID_CRED_I, 4,
                           pk, meas, sizeof(meas), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_BAD_SIGNATURE, "relayed Evidence (different transcript) -> BAD_SIGNATURE");

  uint8_t ref2[34];
  firmware_measurement(ref2);
  ref2[10] ^= 0xFF; /* corrupt the golden reference */
  r = ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                           msg1, sizeof(msg1), msg2, sizeof(msg2), ID_CRED_I, 4,
                           pk, ref2, sizeof(ref2), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_MEASUREMENT_MISMATCH, "reference mismatch -> MEASUREMENT_MISMATCH");
}

int
main(void)
{
  g_pass = g_fail = 0;
  printf("RA-over-EDHOC (draft-ietf-lake-ra) P1 crypto tests\n");
  kat_hkdf_rfc5869();
  kat_binder();
  kat_evidence_flow();
  printf("RESULT: PASS %d FAIL %d\n", g_pass, g_fail);
  printf("%s\n", g_fail == 0 ? "=== ATTESTATION P1 PASSED ===" : "=== ATTESTATION P1 FAILED ===");
  return g_fail;
}
