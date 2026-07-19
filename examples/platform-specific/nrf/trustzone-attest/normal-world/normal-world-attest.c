/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Normal-world firmware for the P2 attestation example -- the ON-DEVICE P2 test
 *   case. It asks the secure world (tz-attest) to produce Evidence about this
 *   normal-world image, fetches the attestation public key, and appraises the
 *   Evidence, printing a PASS/FAIL banner. This is the device-side analog of the
 *   host RoT-core test (tests/2x-attestation/test-attestation-p2.c) and runs in
 *   cooja-ng (nRF5340 model) or on the nRF5340-DK.
 *
 *   A fixed EDHOC transcript stands in for a real handshake; the P1b live-run wires
 *   this to a real EDHOC session (message_1/message_2/ID_CRED_I captured on the fly).
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "contiki.h"
#include "trustzone/tz-api.h"
#include "tz-attest.h"

#include "ra-binder.h"
#include "ra-verifier.h"
#include "ra-cose.h"
#include "ra-eat.h"
#include "monocypher-ed25519.h"

#include <stdio.h>
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "NormalAttest"
#define LOG_LEVEL LOG_LEVEL_INFO

/* NS-side signature verify (Monocypher here; on device could be ed25519_verify.c). */
static int
ns_verify(void *ctx, const uint8_t *pubkey, const uint8_t *msg, size_t msglen,
          const uint8_t sig[64])
{
  (void)ctx;
  return crypto_ed25519_check(sig, pubkey, msg, msglen);
}

/* Stand-in public EDHOC transcript (a real app captures these from the handshake). */
static const uint8_t msg1[12] = { 0x03,0x58,0x08,1,2,3,4,5,6,7,8,0x21 };
static const uint8_t msg2[16] = { 0x58,0x0E,9,8,7,6,5,4,3,2,1,0,0xAA,0xBB,0xCC,0xDD };
static const uint8_t id_cred_i[4] = { 0xA1, 0x04, 0x41, 0x2B };
static const uint8_t nonce[8] = { 0xA2,0x9F,0x62,0xA4,0xC6,0xCD,0xAA,0xE5 };
static const uint8_t ueid[8] = "device01";
/*---------------------------------------------------------------------------*/
PROCESS(normal_attest_process, "Normal-world attestation self-test");
AUTOSTART_PROCESSES(&normal_attest_process);
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(normal_attest_process, ev, data)
{
  static uint8_t binder[RA_BINDER_HASH_LEN];
  static uint8_t evidence[512];
  static uint8_t pk[32];
  static size_t evlen;
  static int ok;
  static struct etimer et;

  PROCESS_BEGIN();

  /* Let the secure world finish initializing (its veneers must be ready). The
   * normal world does not gate on trustzone_init_event -- that is secure-only. */
  etimer_set(&et, 2 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&et));

  /* Normal world computes the (public) attestation binder from the transcript. */
  ra_binder_m3(binder, msg1, sizeof(msg1), msg2, sizeof(msg2), id_cred_i, 4);

  /* Secure world measures this image + signs Evidence. */
  {
    static tz_attest_request_t req;
    req.nonce = nonce; req.noncelen = sizeof(nonce);
    req.ueid = ueid; req.ueidlen = sizeof(ueid);
    req.binder = binder; req.binderlen = sizeof(binder);
    req.out = evidence; req.out_sz = sizeof(evidence);
    ok = (tz_attest_build_evidence(&req) == 0);
    evlen = req.out_len;
  }
  LOG_INFO("tz_attest_build_evidence: %s (%u bytes)\n", ok ? "ok" : "FAIL",
           (unsigned)evlen);
  ok = ok && (tz_attest_public_key(pk) == 0);

  if(ok) {
    /* For this self-test the reference measurement is the one the secure world
     * just reported (extracted from the Evidence) -- a real Verifier compares to a
     * provisioned golden value; the measurement-mismatch check is the host test. */
    const uint8_t *prot, *payload, *sig, *nce, *uid, *meas;
    size_t plen, paylen, siglen, nlen, ulen, mlen;
    uint64_t cf;
    ok = (ra_cose_parse_sign1(evidence, evlen, &prot, &plen, &payload, &paylen,
                              &sig, &siglen) == 0) &&
         (ra_eat_decode_minimal(payload, paylen, &nce, &nlen, &uid, &ulen,
                                &cf, &meas, &mlen) == 0);
    if(ok) {
      ra_appraise_result_t r =
        ra_verifier_appraise(evidence, evlen, nonce, sizeof(nonce),
                             msg1, sizeof(msg1), msg2, sizeof(msg2), id_cred_i, 4,
                             pk, meas, mlen, ns_verify, NULL);
      ok = (r == RA_APPRAISE_PASS);
      LOG_INFO("appraisal result: %d\n", (int)r);
    }
  }

  printf("%s\n", ok ? "=== TZ-ATTEST P2 PASSED ===" : "=== TZ-ATTEST P2 FAILED ===");

  for(;;) {
    PROCESS_WAIT_EVENT();
  }
  PROCESS_END();
}
