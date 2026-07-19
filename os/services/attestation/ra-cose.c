/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   COSE_Sign1 assembly/parse for RA Evidence (see ra-cose.h).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-cose.h"
#include "ra-cbor.h"
/* CBOR reader is vendored in ra-cbor */

const uint8_t ra_cose_protected_eddsa[3] = { 0xA1, 0x01, 0x27 };
const uint8_t ra_cose_protected_es256[3] = { 0xA1, 0x01, 0x26 };

/*---------------------------------------------------------------------------*/
int
ra_cose_sig_structure(uint8_t *out, size_t out_sz, size_t *out_len,
                      const uint8_t *protected, size_t plen,
                      const uint8_t *ext_aad, size_t aadlen,
                      const uint8_t *payload, size_t paylen)
{
  size_t o = 0;
  if(ra_cbor_array(out, out_sz, &o, 4) != 0 ||
     ra_cbor_tstr(out, out_sz, &o, "Signature1", 10) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, protected, plen) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, ext_aad, aadlen) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, payload, paylen) != 0) {
    return -1;
  }
  *out_len = o;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_cose_sign1(uint8_t *out, size_t out_sz, size_t *out_len,
              const uint8_t *protected, size_t plen,
              const uint8_t *payload, size_t paylen,
              const uint8_t *sig, size_t siglen)
{
  size_t o = 0;
  if(ra_cbor_tag(out, out_sz, &o, RA_COSE_SIGN1_TAG) != 0 ||
     ra_cbor_array(out, out_sz, &o, 4) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, protected, plen) != 0 ||
     ra_cbor_map(out, out_sz, &o, 0) != 0 || /* empty unprotected header */
     ra_cbor_bstr(out, out_sz, &o, payload, paylen) != 0 ||
     ra_cbor_bstr(out, out_sz, &o, sig, siglen) != 0) {
    return -1;
  }
  *out_len = o;
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Read one byte-string item at p, returning its content slice + advancing p. */
static int
read_bstr(const uint8_t **p, const uint8_t *end,
          const uint8_t **out, size_t *out_len)
{
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;
  if(ra_cbor_read_head(*p, end, &major, &arg, &body) != 0 || major != RA_CBOR_BSTR) {
    return -1;
  }
  if(body + arg > end) {
    return -1;
  }
  *out = body;
  *out_len = (size_t)arg;
  *p = body + arg;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_cose_parse_sign1(const uint8_t *in, size_t len,
                    const uint8_t **protected, size_t *plen,
                    const uint8_t **payload, size_t *paylen,
                    const uint8_t **sig, size_t *siglen)
{
  const uint8_t *p = in;
  const uint8_t *end = in + len;
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;

  /* tag(18) */
  if(ra_cbor_read_head(p, end, &major, &arg, &body) != 0 || major != 6 || arg != RA_COSE_SIGN1_TAG) {
    return -1;
  }
  p = body;
  /* array(4) */
  if(ra_cbor_read_head(p, end, &major, &arg, &body) != 0 || major != RA_CBOR_ARRAY || arg != 4) {
    return -1;
  }
  p = body;
  /* bstr(protected) */
  if(read_bstr(&p, end, protected, plen) != 0) {
    return -1;
  }
  /* unprotected: empty map {} */
  if(ra_cbor_read_head(p, end, &major, &arg, &body) != 0 || major != RA_CBOR_MAP || arg != 0) {
    return -1;
  }
  p = body;
  /* bstr(payload) */
  if(read_bstr(&p, end, payload, paylen) != 0) {
    return -1;
  }
  /* bstr(signature) */
  if(read_bstr(&p, end, sig, siglen) != 0) {
    return -1;
  }
  if(p != end) {
    return -1; /* trailing data */
  }
  return 0;
}
