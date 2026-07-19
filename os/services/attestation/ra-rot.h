/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Root-of-Trust (RoT) attestation core: measure the target image and produce a
 *   signed Evidence. This is the computation that runs *inside* the Attesting
 *   Environment (RFC 9334 §3.1) -- on the nRF5340 that is the TrustZone secure
 *   world (P2, wrapped by tz-attest), on other platforms it is the single world.
 *
 *   The security property this enforces: the *measurement* is produced by the RoT
 *   (not supplied by the normal world), so a compromised normal world cannot forge
 *   a "good" measurement. The normal world supplies only *public* inputs -- the
 *   Verifier nonce, the ueid, and the attestation binder (computed from the public
 *   EDHOC transcript). The RoT holds the signing key and measures the target.
 *
 *   Portable and self-contained: uses os/lib/sha-256 + ra-attester; the signer is
 *   a pluggable ra_sign_fn (uECC/CC312 in the secure world, Monocypher in tests).
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#ifndef RA_ROT_H
#define RA_ROT_H

#include "ra-attester.h" /* ra_sign_fn */
#include <stdint.h>
#include <stddef.h>

/** Measurement length: CBOR bstr(32) header (0x58 0x20) + a 32-byte SHA-256. */
#define RA_ROT_MEASUREMENT_LEN 34

/** The target to measure (the normal-world application image region). */
typedef struct {
  const uint8_t *image;
  size_t image_len;
} ra_rot_target_t;

/**
 * \brief Measure the target: \p out = CBOR bstr of SHA-256(image). The raw
 *        measurement content used as the EAT measurement claim value.
 * \return 0 on success.
 */
int ra_rot_measure(const ra_rot_target_t *target,
                   uint8_t out[RA_ROT_MEASUREMENT_LEN]);

/**
 * \brief Produce a signed Evidence for the given (public) nonce/ueid/binder: the
 *        RoT measures the target, builds the EAT (with its own measurement), binds
 *        it to \p binder as external_aad, and signs. \p sign is the RoT's signing
 *        primitive (holds/uses the attestation private key).
 * \return 0 on success (Evidence length in \p *out_len), -1 on error.
 */
int ra_rot_build_evidence(const ra_rot_target_t *target,
                          const uint8_t *protected, size_t plen,
                          const uint8_t *nonce, size_t noncelen,
                          const uint8_t *ueid, size_t ueidlen,
                          const uint8_t *binder, size_t binderlen,
                          uint8_t *out, size_t out_sz, size_t *out_len,
                          ra_sign_fn sign, void *sign_ctx);

#endif /* RA_ROT_H */
