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
 * \brief Produce a signed Evidence COSE_Sign1 for the given public inputs. The
 *        secure world measures the NS image, builds the EAT with that measurement,
 *        binds it to \p binder as external_aad, and signs with the secure-resident
 *        attestation key.
 * \param nonce   the Verifier nonce (from EAD_2).
 * \param ueid    the entity unique id claim.
 * \param binder  attestation_binder_m3, computed by the normal world from the
 *                (public) EDHOC message_1/message_2 + ID_CRED_I.
 * \param out     Evidence output buffer (NS memory).
 * \return 0 on success (Evidence length in \p *out_len), non-zero on error.
 */
int tz_attest_build_evidence(const uint8_t *nonce, size_t noncelen,
                             const uint8_t *ueid, size_t ueidlen,
                             const uint8_t *binder, size_t binderlen,
                             uint8_t *out, size_t out_sz, size_t *out_len);

#endif /* TZ_ATTEST_H_ */
