/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Attestation binder -- attest_info encoding (see ra-binder.h). The H_12 hash
 *   and HKDF-Expand derivation are a P1 concern (need the EDHOC transcript + a
 *   SHA-256/HKDF primitive).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-binder.h"
#include "ra-cbor.h"

/*---------------------------------------------------------------------------*/
int
ra_binder_attest_info(uint8_t *out, size_t out_sz, size_t *out_len,
                      const uint8_t *h12, size_t h12len,
                      const uint8_t *id_cred_i, size_t idlen)
{
  size_t o = 0;
  if(ra_cbor_array(out, out_sz, &o, 3) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, h12, h12len) != 0 ||
     ra_cbor_tstr(out, out_sz, &o, "attestation", 11) != 0 ||
     ra_cbor_raw(out, out_sz, &o, id_cred_i, idlen) != 0) {
    return -1;
  }
  *out_len = o;
  return 0;
}
