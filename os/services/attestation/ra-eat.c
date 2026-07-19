/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   EAT minimal-claim-set encode/decode (see ra-eat.h).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-eat.h"
#include "ra-cbor.h"
/* CBOR reader is vendored in ra-cbor */

/*---------------------------------------------------------------------------*/
int
ra_eat_minimal_claims(uint8_t *out, size_t out_sz, size_t *out_len,
                      const uint8_t *nonce, size_t noncelen,
                      const uint8_t *ueid, size_t ueidlen,
                      uint64_t content_format,
                      const uint8_t *measurement, size_t measlen)
{
  size_t o = 0;
  if(ra_cbor_map(out, out_sz, &o, 3) != 0 ||
     ra_cbor_uint(out, out_sz, &o, RA_EAT_CLAIM_NONCE) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, nonce, noncelen) != 0 ||
     ra_cbor_uint(out, out_sz, &o, RA_EAT_CLAIM_UEID) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, ueid, ueidlen) != 0 ||
     ra_cbor_uint(out, out_sz, &o, RA_EAT_CLAIM_MEASUREMENTS) != 0 ||
     ra_cbor_array(out, out_sz, &o, 1) != 0 ||       /* measurements: 1 entry  */
     ra_cbor_array(out, out_sz, &o, 2) != 0 ||       /* [content-format, content] */
     ra_cbor_uint(out, out_sz, &o, content_format) != 0 ||
     ra_cbor_raw(out, out_sz, &o, measurement, measlen) != 0) {
    return -1;
  }
  *out_len = o;
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Read a byte string, returning content slice + advancing p. */
static int
read_bstr(const uint8_t **p, const uint8_t *end, const uint8_t **out, size_t *out_len)
{
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;
  if(ra_cbor_read_head(*p, end, &major, &arg, &body) != 0 || major != RA_CBOR_BSTR ||
     body + arg > end) {
    return -1;
  }
  *out = body;
  *out_len = (size_t)arg;
  *p = body + arg;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_eat_decode_minimal(const uint8_t *in, size_t len,
                      const uint8_t **nonce, size_t *noncelen,
                      const uint8_t **ueid, size_t *ueidlen,
                      uint64_t *content_format,
                      const uint8_t **measurement, size_t *measlen)
{
  const uint8_t *p = in;
  const uint8_t *end = in + len;
  uint8_t major;
  uint64_t npairs;
  const uint8_t *body;
  int have_nonce = 0, have_ueid = 0, have_meas = 0;

  if(ra_cbor_read_head(p, end, &major, &npairs, &body) != 0 || major != RA_CBOR_MAP) {
    return -1;
  }
  p = body;
  for(uint64_t i = 0; i < npairs; i++) {
    uint64_t key;
    if(ra_cbor_read_head(p, end, &major, &key, &body) != 0 || major != RA_CBOR_UINT) {
      return -1;
    }
    p = body;
    if(key == RA_EAT_CLAIM_NONCE) {
      if(read_bstr(&p, end, nonce, noncelen) != 0) {
        return -1;
      }
      have_nonce = 1;
    } else if(key == RA_EAT_CLAIM_UEID) {
      if(read_bstr(&p, end, ueid, ueidlen) != 0) {
        return -1;
      }
      have_ueid = 1;
    } else if(key == RA_EAT_CLAIM_MEASUREMENTS) {
      uint64_t outer, inner;
      /* [ + [content-format, content] ] -- take the first entry. */
      if(ra_cbor_read_head(p, end, &major, &outer, &body) != 0 || major != RA_CBOR_ARRAY ||
         outer < 1) {
        return -1;
      }
      p = body;
      if(ra_cbor_read_head(p, end, &major, &inner, &body) != 0 || major != RA_CBOR_ARRAY ||
         inner != 2) {
        return -1;
      }
      p = body;
      if(ra_cbor_read_head(p, end, &major, content_format, &body) != 0 || major != RA_CBOR_UINT) {
        return -1;
      }
      p = body;
      /* content is a single raw CBOR item; capture it and skip. */
      *measurement = p;
      if(ra_cbor_read_skip(&p, end) != 0) {
        return -1;
      }
      *measlen = (size_t)(p - *measurement);
      have_meas = 1;
      /* Skip any further outer measurement entries. */
      for(uint64_t j = 1; j < outer; j++) {
        if(ra_cbor_read_skip(&p, end) != 0) {
          return -1;
        }
      }
    } else {
      return -1; /* unexpected claim in the minimal set */
    }
  }
  return (have_nonce && have_ueid && have_meas) ? 0 : -1;
}
