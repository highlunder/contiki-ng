/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   TrustZone secure-world attestation Root of Trust (P2 of the draft-ietf-lake-ra
 *   Contiki port). Secure-callable API: the normal world asks the secure world to
 *   produce Evidence about the normal-world image. The secure world holds the
 *   attestation key and *measures* the image, so a compromised normal world cannot
 *   forge a "good" measurement. The normal world supplies only public inputs
 *   (Verifier nonce, ueid, and the attestation binder computed from the EDHOC
 *   transcript). See P2-TRUSTZONE-PLAN.md (in the draft-ietf-lake-ra repo).
 *
 *   Shared between worlds: the secure world DEFINES these (CC_TRUSTZONE_SECURE_CALL,
 *   tz-attest.c); the normal world DECLARES/calls them via this header.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef TZ_ATTEST_H_
#define TZ_ATTEST_H_

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Copy the attestation public key (for Verifier provisioning) out to the
 *        normal world. \return 0 on success, non-zero on an invalid NS pointer.
 */
int tz_attest_public_key(uint8_t out[32]);

/**
 * \brief Evidence request, passed by the normal world to the secure world.
 *
 *   A secure-gateway veneer (cmse_nonsecure_entry) may only take register-passed
 *   arguments, so all inputs/outputs are marshaled through this single struct
 *   (which lives in NS memory; the secure world validates it and every pointer
 *   field before use).
 */
typedef struct {
  const uint8_t *nonce;   /**< Verifier nonce (from EAD_2). */
  size_t noncelen;
  const uint8_t *ueid;    /**< entity unique id claim. */
  size_t ueidlen;
  const uint8_t *binder;  /**< attestation_binder_m3 (NS-computed, public). */
  size_t binderlen;
  uint8_t *out;           /**< Evidence output buffer (NS memory). */
  size_t out_sz;
  size_t out_len;         /**< OUT: Evidence length written. */
} tz_attest_request_t;

/**
 * \brief Produce a signed Evidence COSE_Sign1. The secure world measures the NS
 *        image, builds the EAT with that measurement, binds it to \p req->binder
 *        as external_aad, and signs with the secure-resident attestation key.
 * \return 0 on success (Evidence length in \p req->out_len), non-zero on error.
 */
int tz_attest_build_evidence(tz_attest_request_t *req);

#endif /* TZ_ATTEST_H_ */
