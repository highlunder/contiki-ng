/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Attestation binder (draft-ietf-lake-ra §5.3.3.1). The Evidence COSE_Sign1 is
 *   signed with external_aad set to a binder that ties the Evidence to this EDHOC
 *   session (anti-relay):
 *     attestation_binder_m3 = HKDF-Expand(0, attest_info, hash_len)
 *     attest_info = [ H_12, "attestation", ID_CRED_I ], H_12 = H(H(msg1), msg2)
 *     attestation_binder_m4 = EDHOC_Exporter(2, "attestation", hash_len)
 *
 *   P0 (this file) provides the CBOR part -- attest_info encoding -- which needs
 *   no crypto. The H_12 computation (SHA-256) and HKDF-Expand are wired in P1
 *   against the Contiki EDHOC transcript + HKDF (see CONTIKI-PORT-PLAN.md §7-c);
 *   the draft's Appendix A does not publish the binder inputs, so it is not
 *   KAT-checkable from the draft alone.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_BINDER_H
#define RA_BINDER_H

#include <stdint.h>
#include <stddef.h>

/** EDHOC_Exporter parameters for the message_4 binder (draft §5.3.3.1). */
#define RA_BINDER_M4_EXPORTER_LABEL 2
#define RA_BINDER_M4_EXPORTER_CONTEXT "attestation"

/**
 * \brief Encode attest_info = [ H_12, "attestation", ID_CRED_I ].
 * \param id_cred_i  raw CBOR encoding of ID_CRED_I (embedded verbatim).
 * \return 0 on success (length in \p *out_len), -1 on overflow.
 */
int ra_binder_attest_info(uint8_t *out, size_t out_sz, size_t *out_len,
                          const uint8_t *h12, size_t h12len,
                          const uint8_t *id_cred_i, size_t idlen);

#endif /* RA_BINDER_H */
