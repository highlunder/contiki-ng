/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   cooja-ng / on-device runtime self-test of the RA attestation stack, WITHOUT
 *   TrustZone (single world) so it runs on an emulated nRF52840 (cooja-ng does not
 *   model TrustZone-M; the S/NS split needs the real nRF5340-DK). It exercises the
 *   exact P2 Root-of-Trust flow -- measure a target region, build signed Evidence,
 *   appraise it, and detect a tampered image -- proving the codec + os/lib SHA-256
 *   + the signer run correctly on real ARM (memory/alignment/endianness), not just
 *   on the host. The tz-attest veneer wraps this same flow on the nRF5340.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "contiki.h"
#include "ra-rot.h"
#include "ra-verifier.h"
#include "ra-binder.h"
#include "ra-cose.h"
#include "monocypher-ed25519.h"

#include <stdio.h>
#include <string.h>

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

static const uint8_t msg1[12] = { 0x03,0x58,0x08,1,2,3,4,5,6,7,8,0x21 };
static const uint8_t msg2[16] = { 0x58,0x0E,9,8,7,6,5,4,3,2,1,0,0xAA,0xBB,0xCC,0xDD };
static const uint8_t id_cred_i[4] = { 0xA1, 0x04, 0x41, 0x2B };
static const uint8_t nonce[8] = { 0xA2,0x9F,0x62,0xA4,0xC6,0xCD,0xAA,0xE5 };
static const uint8_t ueid[8] = "device01";

/* The measured target: a stand-in application-image region. */
static uint8_t fw_image[200];
static uint8_t sk[64], pk[32];
static uint8_t binder[RA_BINDER_HASH_LEN];
static uint8_t evidence[512];
static uint8_t golden[RA_ROT_MEASUREMENT_LEN];
/*---------------------------------------------------------------------------*/
PROCESS(attest_selftest, "RA attestation self-test");
AUTOSTART_PROCESSES(&attest_selftest);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(attest_selftest, ev, data)
{
  static int pass, fail;
  static size_t evlen;
  static ra_appraise_result_t r;

  PROCESS_BEGIN();
  pass = fail = 0;

  for(int i = 0; i < 200; i++) {
    fw_image[i] = (uint8_t)(i * 7 + 1);
  }
  {
    uint8_t seed[32];
    for(int i = 0; i < 32; i++) {
      seed[i] = (uint8_t)(0x40 + i);
    }
    crypto_ed25519_key_pair(sk, pk, seed);
  }

  ra_binder_m3(binder, msg1, sizeof(msg1), msg2, sizeof(msg2), id_cred_i, 4);

  /* RoT: measure the image + build+sign Evidence. */
  ra_rot_target_t target = { fw_image, sizeof(fw_image) };
  ra_rot_measure(&target, golden);
  if(ra_rot_build_evidence(&target, ra_cose_protected_eddsa, 3, nonce, sizeof(nonce),
                           ueid, sizeof(ueid), binder, sizeof(binder),
                           evidence, sizeof(evidence), &evlen, mc_sign, sk) == 0) {
    pass++;
    printf("  ok   RoT built Evidence (%u bytes)\n", (unsigned)evlen);
  } else {
    fail++;
    printf("  FAIL RoT build_evidence\n");
  }

  /* Verifier: PASS against the golden measurement. */
  r = ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                           msg1, sizeof(msg1), msg2, sizeof(msg2), id_cred_i, 4,
                           pk, golden, sizeof(golden), mc_verify, NULL);
  if(r == RA_APPRAISE_PASS) { pass++; printf("  ok   Verifier PASS\n"); }
  else { fail++; printf("  FAIL Verifier (%d)\n", (int)r); }

  /* Tamper: flip a byte of the image, re-attest, appraise against the OLD golden. */
  fw_image[123] ^= 0x80;
  ra_rot_build_evidence(&target, ra_cose_protected_eddsa, 3, nonce, sizeof(nonce),
                        ueid, sizeof(ueid), binder, sizeof(binder),
                        evidence, sizeof(evidence), &evlen, mc_sign, sk);
  r = ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                           msg1, sizeof(msg1), msg2, sizeof(msg2), id_cred_i, 4,
                           pk, golden, sizeof(golden), mc_verify, NULL);
  if(r == RA_APPRAISE_MEASUREMENT_MISMATCH) { pass++; printf("  ok   tampered image detected\n"); }
  else { fail++; printf("  FAIL tamper not detected (%d)\n", (int)r); }

  printf("RESULT: PASS %d FAIL %d\n", pass, fail);
  printf("%s\n", fail == 0 ? "=== ATTEST SELFTEST PASSED ===" : "=== ATTEST SELFTEST FAILED ===");

  PROCESS_END();
}
