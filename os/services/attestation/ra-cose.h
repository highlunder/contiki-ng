/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   COSE_Sign1 for RA-over-EDHOC Evidence (draft-ietf-lake-ra §5.3.3/§5.3.3.1).
 *   The Evidence is a COSE_Sign1 whose signature is over a Sig_structure with the
 *   attestation binder as external_aad. This module builds the to-be-signed bytes
 *   and assembles/parses the tagged COSE_Sign1; the actual sign/verify is done by
 *   the platform crypto (os/net/security/cose or c509-rev-verify) once a key is
 *   available -- see CONTIKI-PORT-PLAN.md §7-a.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_COSE_H
#define RA_COSE_H

#include <stdint.h>
#include <stddef.h>

#define RA_COSE_SIGN1_TAG 18

/** COSE protected header content for EdDSA: {1: -8} = A1 01 27. */
extern const uint8_t ra_cose_protected_eddsa[3];
/** COSE protected header content for ES256: {1: -7} = A1 01 26. */
extern const uint8_t ra_cose_protected_es256[3];

/**
 * \brief Build the COSE Sig_structure (the to-be-signed bytes):
 *        [ "Signature1", bstr(protected), bstr(external_aad), bstr(payload) ].
 * \return 0 on success (length in \p *out_len), -1 on overflow.
 */
int ra_cose_sig_structure(uint8_t *out, size_t out_sz, size_t *out_len,
                          const uint8_t *protected, size_t plen,
                          const uint8_t *ext_aad, size_t aadlen,
                          const uint8_t *payload, size_t paylen);

/**
 * \brief Assemble the tagged COSE_Sign1 Evidence object:
 *        18([ bstr(protected), {}, bstr(payload), bstr(signature) ]).
 * \return 0 on success (length in \p *out_len), -1 on overflow.
 */
int ra_cose_sign1(uint8_t *out, size_t out_sz, size_t *out_len,
                  const uint8_t *protected, size_t plen,
                  const uint8_t *payload, size_t paylen,
                  const uint8_t *sig, size_t siglen);

/**
 * \brief Parse a tagged COSE_Sign1 into (protected, payload, signature) slices
 *        (pointers into \p in). \return 0 on success, -1 on malformed input.
 */
int ra_cose_parse_sign1(const uint8_t *in, size_t len,
                        const uint8_t **protected, size_t *plen,
                        const uint8_t **payload, size_t *paylen,
                        const uint8_t **sig, size_t *siglen);

#endif /* RA_COSE_H */
