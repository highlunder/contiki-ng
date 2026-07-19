/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Attester side of RA-over-EDHOC (draft-ietf-lake-ra §5.3.3): build a signed
 *   Evidence COSE_Sign1 bound to the EDHOC transcript. The signature primitive is
 *   supplied by the caller (\ref ra_sign_fn), so the actual signing key + engine
 *   is a backend concern -- a software signer, uECC/CC310, or the nRF5340
 *   TrustZone secure world (P2, tz-attest). The signer signs the COSE
 *   Sig_structure whose external_aad is attestation_binder_m3.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_ATTESTER_H
#define RA_ATTESTER_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Sign \p tbs (the COSE to-be-signed bytes), writing a 64-byte signature.
 *        \p ctx is an opaque backend context (e.g. the private key handle).
 */
typedef void (*ra_sign_fn)(void *ctx, const uint8_t *tbs, size_t tbslen,
                           uint8_t sig[64]);

/**
 * \brief Build a signed Evidence COSE_Sign1 for the (Initiator/Responder,
 *        Background-check) message_3 case: EAT(nonce,ueid,measurement) signed over
 *        the Sig_structure bound to attestation_binder_m3 (from message_1/message_2
 *        + ID_CRED_I).
 * \param protected  COSE protected header content (ra_cose_protected_eddsa/es256).
 * \return 0 on success (Evidence length in \p *out_len), -1 on error.
 */
int ra_attester_build_evidence(uint8_t *out, size_t out_sz, size_t *out_len,
                               const uint8_t *protected, size_t plen,
                               const uint8_t *nonce, size_t noncelen,
                               const uint8_t *ueid, size_t ueidlen,
                               uint64_t content_format,
                               const uint8_t *measurement, size_t measlen,
                               const uint8_t *message_1, size_t m1len,
                               const uint8_t *message_2, size_t m2len,
                               const uint8_t *id_cred_i, size_t idlen,
                               ra_sign_fn sign, void *sign_ctx);

#endif /* RA_ATTESTER_H */
