/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   P1b test: the EDHOC glue (ra-edhoc-glue). Simulates the EDHOC-shaped
 *   (Initiator, Background-check) delivery -- the Attester builds Evidence
 *   (which the app would pass as EAD_3 of edhoc_generate_message_3), the RP's
 *   registered handler (ra_glue_default_handler) receives it as an
 *   edhoc_ead_data_t and appraises it against the captured transcript. This
 *   exercises the real edhoc_ead_data_t type + the glue plumbing end to end,
 *   standalone (Monocypher Ed25519 as the pluggable backend); the remaining P1b
 *   step is running it over a live Contiki EDHOC handshake in cooja-ng.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-edhoc-glue.h"
#include "ra-attester.h"
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
  printf("RA-over-EDHOC (draft-ietf-lake-ra) P1b EDHOC-glue test\n");

  /* Attester keypair + a synthetic captured transcript. */
  uint8_t seed[32], sk[64], pk[32];
  for(int i = 0; i < 32; i++) { seed[i] = (uint8_t)(0x30 + i); }
  crypto_ed25519_key_pair(sk, pk, seed);

  const uint8_t msg1[12] = { 0x03,0x58,0x08,1,2,3,4,5,6,7,8,0x21 };
  const uint8_t msg2[16] = { 0x58,0x0E,9,8,7,6,5,4,3,2,1,0,0xAA,0xBB,0xCC,0xDD };
  const uint8_t nonce[8] = { 0xA2,0x9F,0x62,0xA4,0xC6,0xCD,0xAA,0xE5 };
  const uint8_t *ueid = (const uint8_t *)"device01";
  uint8_t meas[34];
  meas[0] = 0x58; meas[1] = 0x20;
  memset(meas + 2, 0xAB, 32);

  /* Attester builds the Evidence that would ride in EAD_3. */
  uint8_t evidence[512];
  size_t evlen;
  int built = ra_attester_build_evidence(evidence, sizeof(evidence), &evlen,
                                         ra_cose_protected_eddsa, 3,
                                         nonce, sizeof(nonce), ueid, 8,
                                         258, meas, sizeof(meas),
                                         msg1, sizeof(msg1), msg2, sizeof(msg2),
                                         ID_CRED_I, 4, mc_sign, sk);
  CHECK(built == 0, "Attester builds Evidence for EAD_3");

  /* EDHOC would hand the RP the EAD_3 value; the app's handler calls
   * ra_glue_appraise(ead->ead_value, ead->ead_value_sz, &rp). We call it directly
   * with the Evidence bytes here (the `evidence`/`evlen` an EAD item would carry). */
  ra_glue_rp_ctx_t rp = {
    .challenge_nonce = nonce, .noncelen = sizeof(nonce),
    .message_1 = msg1, .m1len = sizeof(msg1),
    .message_2 = msg2, .m2len = sizeof(msg2),
    .id_cred_i = ID_CRED_I, .idlen = 4,
    .attester_pubkey = pk,
    .reference_measurement = meas, .reflen = sizeof(meas),
    .verify = mc_verify, .verify_ctx = NULL,
  };

  ra_appraise_result_t r = ra_glue_appraise(evidence, evlen, &rp);
  CHECK(r == RA_APPRAISE_PASS, "RP appraises EAD_3 Evidence -> PASS (handshake continues)");

  /* A relayed Evidence (RP's transcript differs) must abort the handshake. */
  const uint8_t other_m1[3] = { 0x03, 0xDE, 0xAD };
  rp.message_1 = other_m1;
  rp.m1len = sizeof(other_m1);
  r = ra_glue_appraise(evidence, evlen, &rp);
  CHECK(r == RA_APPRAISE_BAD_SIGNATURE,
        "relayed Evidence (different transcript) -> BAD_SIGNATURE (abort)");

  /* A stale nonce must also abort. */
  rp.message_1 = msg1;
  rp.m1len = sizeof(msg1);
  const uint8_t stale[8] = { 0 };
  rp.challenge_nonce = stale;
  r = ra_glue_appraise(evidence, evlen, &rp);
  CHECK(r == RA_APPRAISE_NONCE_MISMATCH, "stale nonce -> NONCE_MISMATCH (abort)");

  printf("RESULT: PASS %d FAIL %d\n", g_pass, g_fail);
  printf("%s\n", g_fail == 0 ? "=== ATTESTATION P1b PASSED ===" : "=== ATTESTATION P1b FAILED ===");
  return g_fail;
}
