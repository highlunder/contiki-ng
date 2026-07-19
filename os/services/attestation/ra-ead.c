/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Background-check EAD payloads (see ra-ead.h).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-ead.h"
#include "ra-cbor.h"
/* CBOR reader is vendored in ra-cbor */

/*---------------------------------------------------------------------------*/
int
ra_ead_proposed_evidence_types(uint8_t *out, size_t out_sz, size_t *out_len,
                               const uint64_t *content_formats, size_t n)
{
  size_t o = 0;
  if(n == 0) {
    return -1;
  }
  if(ra_cbor_array(out, out_sz, &o, n) != 0) {
    return -1;
  }
  for(size_t i = 0; i < n; i++) {
    if(ra_cbor_uint(out, out_sz, &o, content_formats[i]) != 0) {
      return -1;
    }
  }
  *out_len = o;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_ead_selected_evidence_type(uint8_t *out, size_t out_sz, size_t *out_len,
                              uint64_t content_format,
                              const uint8_t *nonce, size_t noncelen)
{
  size_t o = 0;
  if(noncelen < 8 || noncelen > 64) {
    return -1; /* nonce MUST be 8..64 bytes (RFC 9711) */
  }
  if(ra_cbor_array(out, out_sz, &o, 2) != 0 ||
     ra_cbor_uint(out, out_sz, &o, content_format) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, nonce, noncelen) != 0) {
    return -1;
  }
  *out_len = o;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_ead_decode_selected(const uint8_t *in, size_t len,
                       uint64_t *content_format,
                       const uint8_t **nonce, size_t *noncelen)
{
  const uint8_t *p = in;
  const uint8_t *end = in + len;
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;

  if(ra_cbor_read_head(p, end, &major, &arg, &body) != 0 || major != RA_CBOR_ARRAY || arg != 2) {
    return -1;
  }
  p = body;
  if(ra_cbor_read_head(p, end, &major, content_format, &body) != 0 || major != RA_CBOR_UINT) {
    return -1;
  }
  p = body;
  if(ra_cbor_read_head(p, end, &major, &arg, &body) != 0 || major != RA_CBOR_BSTR ||
     body + arg > end) {
    return -1;
  }
  *nonce = body;
  *noncelen = (size_t)arg;
  p = body + arg;
  return (p == end) ? 0 : -1;
}
