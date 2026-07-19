/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   P2 tests for the Root-of-Trust attestation core (ra-rot) -- the computation
 *   that runs inside the nRF5340 TrustZone secure world (wrapped by tz-attest).
 *   Validates that the RoT *measures* the target (rather than trusting a supplied
 *   measurement) and that a wrong/tampered image is detected by the Verifier.
 *
 *   Standalone (host gcc): os/lib/sha-256 + Monocypher Ed25519 as the RoT signer.
 *   On the nRF5340 the signer is uECC/CC312 in the secure world; the flow is the
 *   same. See P2-TRUSTZONE-PLAN.md.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-rot.h"
#include "ra-verifier.h"
#include "ra-binder.h"
#include "ra-cose.h"
#include "monocypher-ed25519.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_pass, g_fail;
#define CHECK(cond, name) do {                                             \
    if(cond) { g_pass++; printf("  ok   %s\n", (name)); }                  \
    else     { g_fail++; printf("  FAIL %s\n", (name)); }                  \
  } while(0)

/* The RoT's signer (in the secure world; Monocypher here). */
static void
mc_sign(void *ctx, const uint8_t *tbs, size_t tbslen, uint8_t sig[64])
{
  crypto_ed25519_sign(sig, (const uint8_t *)ctx, tbs, tbslen);
}
static int
mc_verify(void *ctx, const uint8_t *pubkey, const uint8_t *msg, size_t msglen,
          const uint8_t sig[64])
{
  (void)ctx;
  return crypto_ed25519_check(sig, pubkey, msg, msglen);
}

static const uint8_t ID_CRED_I[4] = { 0xA1, 0x04, 0x41, 0x2B };

int
main(void)
{
  g_pass = g_fail = 0;
  printf("RA-over-EDHOC (draft-ietf-lake-ra) P2 Root-of-Trust tests\n");

  /* Attestation keypair, held by the RoT (secure world). */
  uint8_t seed[32], sk[64], pk[32];
  for(int i = 0; i < 32; i++) { seed[i] = (uint8_t)(0x40 + i); }
  crypto_ed25519_key_pair(sk, pk, seed);

  /* Two candidate normal-world images: the expected (golden) one and a tampered one. */
  uint8_t image_good[200], image_bad[200];
  for(int i = 0; i < 200; i++) { image_good[i] = (uint8_t)(i * 7 + 1); }
  memcpy(image_bad, image_good, sizeof(image_bad));
  image_bad[123] ^= 0x80; /* a single flipped bit = a different firmware */

  ra_rot_target_t tgt_good = { image_good, sizeof(image_good) };
  ra_rot_target_t tgt_bad = { image_bad, sizeof(image_bad) };

  /* Measurement is a bstr(32) SHA-256; deterministic; distinguishes images. */
  uint8_t m_good[RA_ROT_MEASUREMENT_LEN], m_good2[RA_ROT_MEASUREMENT_LEN], m_bad[RA_ROT_MEASUREMENT_LEN];
  ra_rot_measure(&tgt_good, m_good);
  ra_rot_measure(&tgt_good, m_good2);
  ra_rot_measure(&tgt_bad, m_bad);
  CHECK(m_good[0] == 0x58 && m_good[1] == 0x20, "measurement is CBOR bstr(32)");
  CHECK(memcmp(m_good, m_good2, RA_ROT_MEASUREMENT_LEN) == 0, "measurement deterministic");
  CHECK(memcmp(m_good, m_bad, RA_ROT_MEASUREMENT_LEN) != 0, "measurement distinguishes a tampered image");

  /* EDHOC transcript (public); normal world computes the binder and passes it in. */
  const uint8_t msg1[12] = { 0x03,0x58,0x08,1,2,3,4,5,6,7,8,0x21 };
  const uint8_t msg2[16] = { 0x58,0x0E,9,8,7,6,5,4,3,2,1,0,0xAA,0xBB,0xCC,0xDD };
  const uint8_t nonce[8] = { 0xA2,0x9F,0x62,0xA4,0xC6,0xCD,0xAA,0xE5 };
  const uint8_t *ueid = (const uint8_t *)"device01";
  uint8_t binder[RA_BINDER_HASH_LEN];
  ra_binder_m3(binder, msg1, sizeof(msg1), msg2, sizeof(msg2), ID_CRED_I, 4);

  /* RoT (secure world) measures the running image + signs Evidence. */
  uint8_t evidence[512];
  size_t evlen;
  int built = ra_rot_build_evidence(&tgt_good, ra_cose_protected_eddsa, 3,
                                    nonce, sizeof(nonce), ueid, 8,
                                    binder, sizeof(binder),
                                    evidence, sizeof(evidence), &evlen, mc_sign, sk);
  CHECK(built == 0, "RoT measures the image and signs Evidence");

  /* Verifier accepts when the reference matches the (good) image. */
  ra_appraise_result_t r =
    ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                         msg1, sizeof(msg1), msg2, sizeof(msg2), ID_CRED_I, 4,
                         pk, m_good, sizeof(m_good), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_PASS, "Verifier PASS against the golden reference");

  /* Security property: a device running a *different* image is caught -- the RoT
   * measured the actual image, so the Evidence's measurement != the golden value.
   * (The normal world has no way to inject a false measurement.) */
  uint8_t ev_bad[512];
  size_t ev_bad_len;
  ra_rot_build_evidence(&tgt_bad, ra_cose_protected_eddsa, 3, nonce, sizeof(nonce),
                        ueid, 8, binder, sizeof(binder), ev_bad, sizeof(ev_bad),
                        &ev_bad_len, mc_sign, sk);
  r = ra_verifier_appraise(ev_bad, ev_bad_len, nonce, sizeof(nonce),
                           msg1, sizeof(msg1), msg2, sizeof(msg2), ID_CRED_I, 4,
                           pk, m_good, sizeof(m_good), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_MEASUREMENT_MISMATCH,
        "tampered image detected (Evidence measurement != golden) -> MEASUREMENT_MISMATCH");

  /* The tampered-image Evidence is still a VALID signature over a real measurement
   * (the RoT signed honestly) -- it just does not match the golden reference. */
  r = ra_verifier_appraise(ev_bad, ev_bad_len, nonce, sizeof(nonce),
                           msg1, sizeof(msg1), msg2, sizeof(msg2), ID_CRED_I, 4,
                           pk, m_bad, sizeof(m_bad), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_PASS, "RoT signs honestly (Evidence valid for the actual image)");

  /* Anti-relay is inherited: a different transcript fails the bound signature. */
  const uint8_t other_m1[3] = { 0x03, 0xDE, 0xAD };
  r = ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                           other_m1, sizeof(other_m1), msg2, sizeof(msg2), ID_CRED_I, 4,
                           pk, m_good, sizeof(m_good), mc_verify, NULL);
  CHECK(r == RA_APPRAISE_BAD_SIGNATURE, "relayed Evidence -> BAD_SIGNATURE");

  printf("RESULT: PASS %d FAIL %d\n", g_pass, g_fail);
  printf("%s\n", g_fail == 0 ? "=== ATTESTATION P2 (RoT core) PASSED ===" : "=== ATTESTATION P2 FAILED ===");
  return g_fail;
}
