/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EDHOC <-> RA attestation glue (see ra-edhoc-glue.h). Decoupled from EDHOC:
 *   appraises raw EAD value bytes; the app does the EDHOC-typed marshaling.
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-edhoc-glue.h"

ra_appraise_result_t
ra_glue_appraise(const uint8_t *ead_value, size_t ead_value_sz,
                 const ra_glue_rp_ctx_t *ctx)
{
  if(ctx == NULL || ead_value == NULL) {
    return RA_APPRAISE_MALFORMED;
  }
  return ra_verifier_appraise(ead_value, ead_value_sz,
                              ctx->challenge_nonce, ctx->noncelen,
                              ctx->message_1, ctx->m1len,
                              ctx->message_2, ctx->m2len,
                              ctx->id_cred_i, ctx->idlen,
                              ctx->attester_pubkey,
                              ctx->reference_measurement, ctx->reflen,
                              ctx->verify, ctx->verify_ctx);
}
