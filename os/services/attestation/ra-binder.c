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
#include "lib/sha-256.h"
#include <string.h>

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
/*---------------------------------------------------------------------------*/
void
ra_binder_h12(uint8_t h12[RA_BINDER_HASH_LEN],
              const uint8_t *message_1, size_t m1len,
              const uint8_t *message_2, size_t m2len)
{
  uint8_t h_m1[SHA_256_DIGEST_LENGTH];
  const uint8_t bstr_hdr[2] = { 0x58, 0x20 }; /* CBOR bstr(32) */

  /* H(message_1) */
  sha_256_hash(message_1, m1len, h_m1);
  /* H( bstr(H(message_1)) || message_2 ) */
  SHA_256.init();
  SHA_256.update(bstr_hdr, sizeof(bstr_hdr));
  SHA_256.update(h_m1, sizeof(h_m1));
  SHA_256.update(message_2, m2len);
  SHA_256.finalize(h12);
}
/*---------------------------------------------------------------------------*/
int
ra_binder_m3(uint8_t binder[RA_BINDER_HASH_LEN],
             const uint8_t *message_1, size_t m1len,
             const uint8_t *message_2, size_t m2len,
             const uint8_t *id_cred_i, size_t idlen)
{
  uint8_t h12[RA_BINDER_HASH_LEN];
  uint8_t info[16 + RA_BINDER_HASH_LEN + 64]; /* array + bstr(32) + "attestation" + ID_CRED_I */
  uint8_t prk[RA_BINDER_HASH_LEN];
  size_t infolen;

  ra_binder_h12(h12, message_1, m1len, message_2, m2len);
  if(ra_binder_attest_info(info, sizeof(info), &infolen, h12, sizeof(h12),
                           id_cred_i, idlen) != 0) {
    return -1;
  }
  memset(prk, 0, sizeof(prk)); /* PRK = 0^hash_len */
  sha_256_hkdf_expand(prk, sizeof(prk), info, infolen, binder, RA_BINDER_HASH_LEN);
  return 0;
}
