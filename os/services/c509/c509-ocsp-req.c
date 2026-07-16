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
 *   On-device C509 OCSP request builders — see c509-ocsp-req.h.
 */

#include "c509-ocsp-req.h"
#include <string.h>

/* --- minimal deterministic CBOR writer (definite-length, minimal args) --- */

/* Write a CBOR head (major type + argument, minimal-length encoding). */
static int
wr_head(uint8_t *b, size_t sz, size_t *off, uint8_t major, uint64_t arg)
{
  uint8_t mt = (uint8_t)(major << 5);
  if(arg < 24) {
    if(*off + 1 > sz) { return -1; }
    b[(*off)++] = mt | (uint8_t)arg;
  } else if(arg < 0x100) {
    if(*off + 2 > sz) { return -1; }
    b[(*off)++] = mt | 24;
    b[(*off)++] = (uint8_t)arg;
  } else if(arg < 0x10000) {
    if(*off + 3 > sz) { return -1; }
    b[(*off)++] = mt | 25;
    b[(*off)++] = (uint8_t)(arg >> 8);
    b[(*off)++] = (uint8_t)arg;
  } else if(arg < 0x100000000ULL) {
    if(*off + 5 > sz) { return -1; }
    b[(*off)++] = mt | 26;
    b[(*off)++] = (uint8_t)(arg >> 24);
    b[(*off)++] = (uint8_t)(arg >> 16);
    b[(*off)++] = (uint8_t)(arg >> 8);
    b[(*off)++] = (uint8_t)arg;
  } else {
    if(*off + 9 > sz) { return -1; }
    b[(*off)++] = mt | 27;
    for(int i = 7; i >= 0; i--) {
      b[(*off)++] = (uint8_t)(arg >> (i * 8));
    }
  }
  return 0;
}

static int
wr_int(uint8_t *b, size_t sz, size_t *off, int64_t v)
{
  if(v >= 0) {
    return wr_head(b, sz, off, 0 /* uint */, (uint64_t)v);
  }
  return wr_head(b, sz, off, 1 /* nint */, (uint64_t)(-1 - v));
}

static int
wr_bstr(uint8_t *b, size_t sz, size_t *off, const uint8_t *data, size_t len)
{
  if(wr_head(b, sz, off, 2 /* bstr */, (uint64_t)len) != 0) {
    return -1;
  }
  if(*off + len > sz) { return -1; }
  memcpy(b + *off, data, len);
  *off += len;
  return 0;
}

static int
wr_array(uint8_t *b, size_t sz, size_t *off, uint64_t n)
{
  return wr_head(b, sz, off, 4 /* array */, n);
}

static int
wr_null(uint8_t *b, size_t sz, size_t *off)
{
  if(*off + 1 > sz) { return -1; }
  b[(*off)++] = 0xf6;
  return 0;
}

/* Write a nonce field: a byte string, or null when absent. */
static int
wr_nonce(uint8_t *b, size_t sz, size_t *off, const uint8_t *nonce, size_t len)
{
  if(nonce == NULL || len == 0) {
    return wr_null(b, sz, off);
  }
  return wr_bstr(b, sz, off, nonce, len);
}

int
c509_ocsp_build_simple_request(uint8_t *out, size_t out_size, size_t *out_len,
                               int64_t hash_alg,
                               const uint8_t *nonce, size_t nonce_len,
                               const uint8_t *issuer_cert_hash,
                               size_t issuer_hash_len,
                               const uint8_t *serial_number_hash,
                               size_t serial_hash_len)
{
  if(out == NULL || out_len == NULL || issuer_cert_hash == NULL ||
     serial_number_hash == NULL) {
    return -1;
  }
  size_t off = 0;
  /* [2, hashAlgorithm, nonce, issuerCertHash, serialNumberHash, extensions] */
  if(wr_array(out, out_size, &off, 6) != 0 ||
     wr_int(out, out_size, &off, 2) != 0 ||
     wr_int(out, out_size, &off, hash_alg) != 0 ||
     wr_nonce(out, out_size, &off, nonce, nonce_len) != 0 ||
     wr_bstr(out, out_size, &off, issuer_cert_hash, issuer_hash_len) != 0 ||
     wr_bstr(out, out_size, &off, serial_number_hash, serial_hash_len) != 0 ||
     wr_array(out, out_size, &off, 0) != 0) {
    return -1;
  }
  *out_len = off;
  return 0;
}

int
c509_ocsp_build_unsigned_request(uint8_t *out, size_t out_size, size_t *out_len,
                                 int64_t hash_alg,
                                 const uint8_t *nonce, size_t nonce_len,
                                 const c509_ocsp_group_t *groups,
                                 size_t n_groups)
{
  if(out == NULL || out_len == NULL || (groups == NULL && n_groups != 0)) {
    return -1;
  }
  size_t off = 0;
  /* [0, hashAlgorithm, nonce, extensions, requests] */
  if(wr_array(out, out_size, &off, 5) != 0 ||
     wr_int(out, out_size, &off, 0) != 0 ||
     wr_int(out, out_size, &off, hash_alg) != 0 ||
     wr_nonce(out, out_size, &off, nonce, nonce_len) != 0 ||
     wr_array(out, out_size, &off, 0) != 0) {    /* top-level extensions */
    return -1;
  }
  /* requests: array of 3-element PerIssuer groups
   * (issuerCertHash, extensions, singleRequests). */
  if(wr_array(out, out_size, &off, (uint64_t)n_groups * 3) != 0) {
    return -1;
  }
  for(size_t g = 0; g < n_groups; g++) {
    const c509_ocsp_group_t *grp = &groups[g];
    if(grp->issuer_cert_hash == NULL ||
       (grp->singles == NULL && grp->n_singles != 0)) {
      return -1;
    }
    if(wr_bstr(out, out_size, &off, grp->issuer_cert_hash, grp->issuer_hash_len) != 0 ||
       wr_array(out, out_size, &off, 0) != 0) {   /* per-issuer extensions */
      return -1;
    }
    /* singleRequests: array of 2-element (serialNumberHash, extensions). */
    if(wr_array(out, out_size, &off, (uint64_t)grp->n_singles * 2) != 0) {
      return -1;
    }
    for(size_t s = 0; s < grp->n_singles; s++) {
      if(grp->singles[s].serial_number_hash == NULL) {
        return -1;
      }
      if(wr_bstr(out, out_size, &off, grp->singles[s].serial_number_hash,
                 grp->singles[s].serial_hash_len) != 0 ||
         wr_array(out, out_size, &off, 0) != 0) { /* per-single extensions */
        return -1;
      }
    }
  }
  *out_len = off;
  return 0;
}
