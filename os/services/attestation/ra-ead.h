/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Background-check EAD payloads for RA-over-EDHOC (draft-ietf-lake-ra §5.3):
 *   Attestation_proposal (Proposed_EvidenceType) and Attestation_request
 *   (Selected_EvidenceType = [content-format, nonce]). The Passport-model
 *   payloads (Result_*) are added in a later phase; P0 covers the BG negotiation.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_EAD_H
#define RA_EAD_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief Encode Proposed_EvidenceType = [ + content-format ] (>= 1).
 * \return 0 on success (length in \p *out_len), -1 on overflow/empty.
 */
int ra_ead_proposed_evidence_types(uint8_t *out, size_t out_sz, size_t *out_len,
                                   const uint64_t *content_formats, size_t n);

/**
 * \brief Encode Selected_EvidenceType = [content-format, nonce] (nonce 8..64 B).
 * \return 0 on success (length in \p *out_len), -1 on overflow/bad nonce.
 */
int ra_ead_selected_evidence_type(uint8_t *out, size_t out_sz, size_t *out_len,
                                  uint64_t content_format,
                                  const uint8_t *nonce, size_t noncelen);

/**
 * \brief Decode Selected_EvidenceType, returning the content-format and a slice
 *        into \p in for the nonce. \return 0 on success, -1 on malformed input.
 */
int ra_ead_decode_selected(const uint8_t *in, size_t len,
                           uint64_t *content_format,
                           const uint8_t **nonce, size_t *noncelen);

#endif /* RA_EAD_H */
