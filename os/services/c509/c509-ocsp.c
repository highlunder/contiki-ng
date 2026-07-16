/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * \file
 *   On-device C509 OCSP response status codec — see c509-ocsp.h.
 */

#include "c509-ocsp.h"
#include "c509-cbor-lite.h"
#include <string.h>

/* Read a CBOR byte string at *pp: set ptr,plen to its content, advance *pp. */
static int
read_bstr(const uint8_t **pp, const uint8_t *end,
          const uint8_t **ptr, size_t *plen)
{
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;
  if(c509_cbor_head(*pp, end, &major, &arg, &body) != 0 ||
     major != C509_CBOR_BSTR || body + arg > end) {
    return -1;
  }
  *ptr = body;
  *plen = (size_t)arg;
  *pp = body + arg;
  return 0;
}

/* Read a CBOR unsigned int at *pp into *v, advance *pp. */
static int
read_uint(const uint8_t **pp, const uint8_t *end, uint64_t *v)
{
  uint8_t major;
  const uint8_t *body;
  if(c509_cbor_head(*pp, end, &major, v, &body) != 0 || major != C509_CBOR_UINT) {
    return -1;
  }
  *pp = body;
  return 0;
}

/* Parse a CertStatus item at *pp into result, advance *pp.
 *   uint 0/1/2         -> good / not-issued / unknown
 *   array(2) [t, r]    -> revoked (t = revocationTime uint, r = reason int) */
static int
parse_cert_status(const uint8_t **pp, const uint8_t *end,
                  c509_ocsp_result_t *result)
{
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;
  if(c509_cbor_head(*pp, end, &major, &arg, &body) != 0) {
    return -1;
  }
  if(major == C509_CBOR_UINT) {
    if(arg > 2) {
      return -1;
    }
    result->status = (c509_ocsp_status_t)arg;
    result->revocation_time = 0;
    result->revocation_reason = 0;
    *pp = body;
    return 0;
  }
  if(major == C509_CBOR_ARRAY && arg == 2) {
    const uint8_t *q = body;
    /* revocationTime: absolute time (uint). */
    if(read_uint(&q, end, &result->revocation_time) != 0) {
      return -1;
    }
    /* revocationReason: int (uint or nint). */
    uint8_t m2;
    uint64_t a2;
    const uint8_t *b2;
    if(c509_cbor_head(q, end, &m2, &a2, &b2) != 0) {
      return -1;
    }
    if(m2 == C509_CBOR_UINT) {
      result->revocation_reason = (int64_t)a2;
    } else if(m2 == C509_CBOR_NINT) {
      result->revocation_reason = -1 - (int64_t)a2;
    } else {
      return -1;
    }
    result->status = C509_OCSP_REVOKED;
    *pp = b2;
    return 0;
  }
  return -1;
}

/* Match helper: are two byte spans equal? */
static int
hash_eq(const uint8_t *a, size_t alen, const uint8_t *b, size_t blen)
{
  return alen == blen && memcmp(a, b, alen) == 0;
}

int
c509_ocsp_resp_type(const uint8_t *buf, size_t len)
{
  if(buf == NULL || len == 0) {
    return -1;
  }
  const uint8_t *end = buf + len;
  uint8_t major;
  uint64_t n;
  const uint8_t *body;
  if(c509_cbor_head(buf, end, &major, &n, &body) != 0 ||
     major != C509_CBOR_ARRAY || n < 2) {
    return -1;
  }
  uint64_t t;
  const uint8_t *p = body;
  if(read_uint(&p, end, &t) != 0 || t > 2) {
    return -1;
  }
  return (int)t;
}

int
c509_ocsp_error_status(const uint8_t *buf, size_t len, int64_t *status_out)
{
  if(status_out == NULL || c509_ocsp_resp_type(buf, len) != 0) {
    return -1;
  }
  const uint8_t *end = buf + len;
  uint8_t major;
  uint64_t n;
  const uint8_t *body;
  if(c509_cbor_head(buf, end, &major, &n, &body) != 0) {
    return -1;
  }
  const uint8_t *p = body;
  uint64_t t;
  if(read_uint(&p, end, &t) != 0) {          /* type */
    return -1;
  }
  /* responseStatus: int (uint or nint). */
  uint8_t m;
  uint64_t a;
  const uint8_t *b;
  if(c509_cbor_head(p, end, &m, &a, &b) != 0) {
    return -1;
  }
  if(m == C509_CBOR_UINT) {
    *status_out = (int64_t)a;
  } else if(m == C509_CBOR_NINT) {
    *status_out = -1 - (int64_t)a;
  } else {
    return -1;
  }
  return 0;
}

/* Simple response (type 2): single (issuerCertHash, serialNumberHash, status).
 * `p` is positioned just after the type element. */
static int
lookup_simple(const uint8_t *p, const uint8_t *end,
              const uint8_t *ih, size_t ihl,
              const uint8_t *sh, size_t shl,
              c509_ocsp_result_t *result)
{
  /* skip sigAlg, hashAlg, nonce, responderCertHash (elements 1..4) */
  for(int i = 0; i < 4; i++) {
    if(c509_cbor_skip(&p, end) != 0) {
      return -1;
    }
  }
  const uint8_t *ich, *snh;
  size_t ich_l, snh_l;
  if(read_bstr(&p, end, &ich, &ich_l) != 0) {  /* issuerCertHash */
    return -1;
  }
  if(read_bstr(&p, end, &snh, &snh_l) != 0) {  /* serialNumberHash */
    return -1;
  }
  if(!hash_eq(ich, ich_l, ih, ihl) || !hash_eq(snh, snh_l, sh, shl)) {
    return 1;   /* not the target */
  }
  return parse_cert_status(&p, end, result) == 0 ? 0 : -1;
}

/* Basic response (type 1): walk `responses` groups. `p` is just after type. */
static int
lookup_basic(const uint8_t *p, const uint8_t *end,
             const uint8_t *ih, size_t ihl,
             const uint8_t *sh, size_t shl,
             c509_ocsp_result_t *result)
{
  /* skip sigAlg, hashAlg, nonce, responderCertHash, producedAt, extensions
   * (elements 1..6) to reach `responses` (element 7). */
  for(int i = 0; i < 6; i++) {
    if(c509_cbor_skip(&p, end) != 0) {
      return -1;
    }
  }
  uint8_t major;
  uint64_t nresp;
  const uint8_t *body;
  if(c509_cbor_head(p, end, &major, &nresp, &body) != 0 ||
     major != C509_CBOR_ARRAY || (nresp % 3) != 0) {
    return -1;
  }
  p = body;
  uint64_t groups = nresp / 3;
  for(uint64_t g = 0; g < groups; g++) {
    const uint8_t *ich;
    size_t ich_l;
    if(read_bstr(&p, end, &ich, &ich_l) != 0) {  /* issuerCertHash */
      return -1;
    }
    if(c509_cbor_skip(&p, end) != 0) {           /* extensions */
      return -1;
    }
    /* singleResponses: array of 5*singles elements. */
    uint64_t nsingle;
    if(c509_cbor_head(p, end, &major, &nsingle, &body) != 0 ||
       major != C509_CBOR_ARRAY || (nsingle % 5) != 0) {
      return -1;
    }
    p = body;
    uint64_t singles = nsingle / 5;
    int issuer_match = hash_eq(ich, ich_l, ih, ihl);
    for(uint64_t s = 0; s < singles; s++) {
      const uint8_t *snh;
      size_t snh_l;
      if(read_bstr(&p, end, &snh, &snh_l) != 0) {  /* serialNumberHash */
        return -1;
      }
      if(issuer_match && hash_eq(snh, snh_l, sh, shl)) {
        return parse_cert_status(&p, end, result) == 0 ? 0 : -1;
      }
      /* not the target: skip certStatus, thisUpdate, nextUpdate, extensions */
      for(int i = 0; i < 4; i++) {
        if(c509_cbor_skip(&p, end) != 0) {
          return -1;
        }
      }
    }
  }
  return 1;   /* no matching entry */
}

int
c509_ocsp_lookup(const uint8_t *buf, size_t len,
                 const uint8_t *issuer_cert_hash, size_t issuer_hash_len,
                 const uint8_t *serial_number_hash, size_t serial_hash_len,
                 c509_ocsp_result_t *result)
{
  if(buf == NULL || issuer_cert_hash == NULL || serial_number_hash == NULL ||
     result == NULL) {
    return -1;
  }
  const uint8_t *end = buf + len;
  uint8_t major;
  uint64_t n;
  const uint8_t *body;
  if(c509_cbor_head(buf, end, &major, &n, &body) != 0 ||
     major != C509_CBOR_ARRAY || n < 2) {
    return -1;
  }
  const uint8_t *p = body;
  uint64_t type;
  if(read_uint(&p, end, &type) != 0) {
    return -1;
  }
  if(type == 1) {
    return lookup_basic(p, end, issuer_cert_hash, issuer_hash_len,
                        serial_number_hash, serial_hash_len, result);
  }
  if(type == 2) {
    return lookup_simple(p, end, issuer_cert_hash, issuer_hash_len,
                         serial_number_hash, serial_hash_len, result);
  }
  return -1;   /* Error response (0) or unknown: no per-cert status */
}
