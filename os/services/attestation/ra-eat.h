/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EAT (Entity Attestation Token, RFC 9711) minimal-claim-set for RA Evidence
 *   (draft-ietf-lake-ra §5.3.3): { 10: eat_nonce, 256: ueid, 273: measurements }
 *   where measurements = [ + [content-format, content] ]. The measurement content
 *   is embedded as a raw CBOR item (matching the draft Appendix A; see the
 *   SPEC-REVIEW note in the Rust reference impl about the CDDL `bytes` vs example).
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_EAT_H
#define RA_EAT_H

#include <stdint.h>
#include <stddef.h>

#define RA_EAT_CLAIM_NONCE        10
#define RA_EAT_CLAIM_UEID        256
#define RA_EAT_CLAIM_MEASUREMENTS 273

/**
 * \brief Encode a minimal-claim-set EAT payload (one measurement).
 * \param measurement  raw, already-CBOR-encoded measurement content.
 * \return 0 on success (length in \p *out_len), -1 on overflow.
 */
int ra_eat_minimal_claims(uint8_t *out, size_t out_sz, size_t *out_len,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ueid, size_t ueidlen,
                          uint64_t content_format,
                          const uint8_t *measurement, size_t measlen);

/**
 * \brief Decode a minimal-claim-set EAT payload, returning slices into \p in for
 *        the nonce, ueid and the first measurement's content.
 * \return 0 on success, -1 on malformed input.
 */
int ra_eat_decode_minimal(const uint8_t *in, size_t len,
                          const uint8_t **nonce, size_t *noncelen,
                          const uint8_t **ueid, size_t *ueidlen,
                          uint64_t *content_format,
                          const uint8_t **measurement, size_t *measlen);

#endif /* RA_EAT_H */
