/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Verifier appraisal of background-check Evidence (see ra-verifier.h).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-verifier.h"
#include "ra-cose.h"
#include "ra-eat.h"
#include "ra-binder.h"
#include <string.h>

ra_appraise_result_t
ra_verifier_appraise(const uint8_t *evidence, size_t evlen,
                     const uint8_t *challenge_nonce, size_t noncelen,
                     const uint8_t *message_1, size_t m1len,
                     const uint8_t *message_2, size_t m2len,
                     const uint8_t *id_cred_i, size_t idlen,
                     const uint8_t *attester_pubkey,
                     const uint8_t *reference_measurement, size_t reflen,
                     ra_verify_fn verify, void *verify_ctx)
{
  const uint8_t *protected, *payload, *sig;
  size_t plen, paylen, siglen;
  const uint8_t *ev_nonce, *ev_ueid, *ev_meas;
  size_t nlen, ulen, mlen;
  uint64_t cf;
  uint8_t binder[RA_BINDER_HASH_LEN];
  uint8_t tbs[512];
  size_t tbslen;

  if(ra_cose_parse_sign1(evidence, evlen, &protected, &plen,
                         &payload, &paylen, &sig, &siglen) != 0 || siglen != 64) {
    return RA_APPRAISE_MALFORMED;
  }
  if(ra_eat_decode_minimal(payload, paylen, &ev_nonce, &nlen, &ev_ueid, &ulen,
                           &cf, &ev_meas, &mlen) != 0) {
    return RA_APPRAISE_MALFORMED;
  }

  /* Freshness: the EAT nonce must match the Verifier's challenge. */
  if(noncelen == 0 || nlen != noncelen || memcmp(ev_nonce, challenge_nonce, noncelen) != 0) {
    return RA_APPRAISE_NONCE_MISMATCH;
  }

  /* Anti-relay: recompute the binder from the Verifier's own transcript view. */
  if(ra_binder_m3(binder, message_1, m1len, message_2, m2len, id_cred_i, idlen) != 0) {
    return RA_APPRAISE_MALFORMED;
  }
  if(ra_cose_sig_structure(tbs, sizeof(tbs), &tbslen, protected, plen,
                           binder, sizeof(binder), payload, paylen) != 0) {
    return RA_APPRAISE_MALFORMED;
  }
  if(verify(verify_ctx, attester_pubkey, tbs, tbslen, sig) != 0) {
    return RA_APPRAISE_BAD_SIGNATURE;
  }

  /* Reference-value appraisal (simplest policy: byte-exact golden value). */
  if(mlen != reflen || memcmp(ev_meas, reference_measurement, reflen) != 0) {
    return RA_APPRAISE_MEASUREMENT_MISMATCH;
  }
  return RA_APPRAISE_PASS;
}
