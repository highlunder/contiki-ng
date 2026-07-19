/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Attester: build a transcript-bound Evidence COSE_Sign1 (see ra-attester.h).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-attester.h"
#include "ra-eat.h"
#include "ra-cose.h"
#include "ra-binder.h"

int
ra_attester_build_evidence_with_binder(uint8_t *out, size_t out_sz, size_t *out_len,
                                       const uint8_t *protected, size_t plen,
                                       const uint8_t *nonce, size_t noncelen,
                                       const uint8_t *ueid, size_t ueidlen,
                                       uint64_t content_format,
                                       const uint8_t *measurement, size_t measlen,
                                       const uint8_t *binder, size_t binderlen,
                                       ra_sign_fn sign, void *sign_ctx)
{
  uint8_t payload[256];
  uint8_t tbs[512];
  uint8_t sig[64];
  size_t paylen, tbslen;

  if(ra_eat_minimal_claims(payload, sizeof(payload), &paylen, nonce, noncelen,
                           ueid, ueidlen, content_format, measurement, measlen) != 0) {
    return -1;
  }
  if(ra_cose_sig_structure(tbs, sizeof(tbs), &tbslen, protected, plen,
                           binder, binderlen, payload, paylen) != 0) {
    return -1;
  }
  sign(sign_ctx, tbs, tbslen, sig);
  return ra_cose_sign1(out, out_sz, out_len, protected, plen, payload, paylen,
                       sig, sizeof(sig));
}
/*---------------------------------------------------------------------------*/
int
ra_attester_build_evidence(uint8_t *out, size_t out_sz, size_t *out_len,
                           const uint8_t *protected, size_t plen,
                           const uint8_t *nonce, size_t noncelen,
                           const uint8_t *ueid, size_t ueidlen,
                           uint64_t content_format,
                           const uint8_t *measurement, size_t measlen,
                           const uint8_t *message_1, size_t m1len,
                           const uint8_t *message_2, size_t m2len,
                           const uint8_t *id_cred_i, size_t idlen,
                           ra_sign_fn sign, void *sign_ctx)
{
  uint8_t binder[RA_BINDER_HASH_LEN];

  if(ra_binder_m3(binder, message_1, m1len, message_2, m2len, id_cred_i, idlen) != 0) {
    return -1;
  }
  return ra_attester_build_evidence_with_binder(out, out_sz, out_len, protected, plen,
                                                nonce, noncelen, ueid, ueidlen,
                                                content_format, measurement, measlen,
                                                binder, sizeof(binder), sign, sign_ctx);
}
