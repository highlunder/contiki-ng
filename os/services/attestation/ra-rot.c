/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Root-of-Trust attestation core: measure + build signed Evidence (see ra-rot.h).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-rot.h"
#include "lib/sha-256.h"
#include <string.h>

int
ra_rot_measure(const ra_rot_target_t *target, uint8_t out[RA_ROT_MEASUREMENT_LEN])
{
  if(target == NULL || target->image == NULL) {
    return -1;
  }
  out[0] = 0x58; /* CBOR bstr, 1-byte length */
  out[1] = 0x20; /* length 32 */
  sha_256_hash(target->image, target->image_len, out + 2);
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_rot_build_evidence(const ra_rot_target_t *target,
                      const uint8_t *protected, size_t plen,
                      const uint8_t *nonce, size_t noncelen,
                      const uint8_t *ueid, size_t ueidlen,
                      const uint8_t *binder, size_t binderlen,
                      uint8_t *out, size_t out_sz, size_t *out_len,
                      ra_sign_fn sign, void *sign_ctx)
{
  uint8_t measurement[RA_ROT_MEASUREMENT_LEN];

  /* The measurement is produced HERE (by the RoT), not supplied by the caller. */
  if(ra_rot_measure(target, measurement) != 0) {
    return -1;
  }
  return ra_attester_build_evidence_with_binder(out, out_sz, out_len, protected, plen,
                                                nonce, noncelen, ueid, ueidlen,
                                                258, measurement, sizeof(measurement),
                                                binder, binderlen, sign, sign_ctx);
}
