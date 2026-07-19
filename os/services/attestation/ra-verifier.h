/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Verifier / Relying-Party appraisal of background-check Evidence
 *   (draft-ietf-lake-ra §8.1): parse the Evidence COSE_Sign1, check nonce
 *   freshness, recompute the attestation binder from the Verifier's own
 *   transcript view (anti-relay), verify the signature via a caller-supplied
 *   primitive (\ref ra_verify_fn), and match the measurement against a reference
 *   value. The signature engine is pluggable (ed25519_verify, uECC/CC310, ...).
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_VERIFIER_H
#define RA_VERIFIER_H

#include <stdint.h>
#include <stddef.h>

/** \brief Verify a 64-byte signature over \p msg with \p pubkey. Return 0 iff
 *         valid. \p ctx is an opaque backend context. */
typedef int (*ra_verify_fn)(void *ctx, const uint8_t *pubkey,
                            const uint8_t *msg, size_t msglen,
                            const uint8_t sig[64]);

typedef enum {
  RA_APPRAISE_PASS = 0,
  RA_APPRAISE_MALFORMED,
  RA_APPRAISE_NONCE_MISMATCH,
  RA_APPRAISE_BAD_SIGNATURE,
  RA_APPRAISE_MEASUREMENT_MISMATCH
} ra_appraise_result_t;

/**
 * \brief Appraise a message_3 background-check Evidence.
 * \param attester_pubkey  the Attester's attestation public key (verify input).
 * \param reference_measurement  the expected (golden) measurement content.
 * \return an ra_appraise_result_t.
 */
ra_appraise_result_t
ra_verifier_appraise(const uint8_t *evidence, size_t evlen,
                     const uint8_t *challenge_nonce, size_t noncelen,
                     const uint8_t *message_1, size_t m1len,
                     const uint8_t *message_2, size_t m2len,
                     const uint8_t *id_cred_i, size_t idlen,
                     const uint8_t *attester_pubkey,
                     const uint8_t *reference_measurement, size_t reflen,
                     ra_verify_fn verify, void *verify_ctx);

#endif /* RA_VERIFIER_H */
