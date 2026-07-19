/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Glue between the RA attestation codec and the Contiki-NG EDHOC impl
 *   (os/net/security/edhoc). Kept fully decoupled from EDHOC (no EDHOC headers,
 *   no link dependency): it appraises the *raw EAD value bytes*, and the
 *   application does the EDHOC-typed marshaling. This keeps os/services/attestation
 *   self-contained and standalone-testable.
 *
 *   Relying-Party integration pattern (the app writes ~4 lines):
 *   \code
 *     static ra_glue_rp_ctx_t rp;   // filled with nonce, captured msg_1/msg_2,
 *                                   // ID_CRED_I, attester_pubkey, reference, verify fn
 *     static edhoc_error_t ra_handler(const edhoc_ead_data_t *ead) {
 *       return ra_glue_appraise(ead->ead_value, ead->ead_value_sz, &rp)
 *              == RA_APPRAISE_PASS ? EDHOC_SUCCESS : EDHOC_ERR_CRYPTO_VERIFY;
 *     }
 *     edhoc_register_ead_handler(RA_GLUE_EAD_LABEL, ra_handler);
 *   \endcode
 *
 *   Attester integration: build Evidence with ra_attester_build_evidence() (using
 *   the captured message_1/message_2 + ID_CRED_I + a signer) and pass it as the
 *   auth_data (EAD) of edhoc_generate_message_3(). EDHOC reuses its rx/tx buffers
 *   across messages, so the app must copy message_1 (when it generates it) and
 *   message_2 (when it receives it) out for the binder.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_EDHOC_GLUE_H
#define RA_EDHOC_GLUE_H

#include "ra-verifier.h" /* ra_verify_fn, ra_appraise_result_t */
#include <stdint.h>
#include <stddef.h>

/** Provisional RA EAD label (draft §10.1 TBD1). Non-critical positive for the
 *  (I, Background-check) demo; a critical label would be negative (RFC 9528 §6). */
#define RA_GLUE_EAD_LABEL 20

/** Relying-Party appraisal context. The transcript (message_1/message_2) and
 *  ID_CRED_I are captured by the app during the handshake. */
typedef struct {
  const uint8_t *challenge_nonce; /* the Verifier nonce sent in EAD_2 */
  size_t noncelen;
  const uint8_t *message_1;
  size_t m1len;
  const uint8_t *message_2;
  size_t m2len;
  const uint8_t *id_cred_i;
  size_t idlen;
  const uint8_t *attester_pubkey; /* Attester attestation public key */
  const uint8_t *reference_measurement;
  size_t reflen;
  ra_verify_fn verify; /* signature-verify backend */
  void *verify_ctx;
} ra_glue_rp_ctx_t;

/**
 * \brief Appraise the raw Evidence bytes carried in an EDHOC EAD value against
 *        \p ctx (nonce freshness + transcript-bound signature + reference value).
 *        The caller maps the result to EDHOC_SUCCESS (PASS) / a negative
 *        edhoc_error_t (abort) in its edhoc_ead_handler_fn.
 */
ra_appraise_result_t ra_glue_appraise(const uint8_t *ead_value, size_t ead_value_sz,
                                      const ra_glue_rp_ctx_t *ctx);

#endif /* RA_EDHOC_GLUE_H */
