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
 *   On-device C509 CRL parser + revocation lookup — see c509-crl.h.
 */

#include "c509-crl.h"
#include <string.h>

/* Minimal CBOR major types (high 3 bits of the initial byte). */
#define CBOR_UINT   0
#define CBOR_NINT   1
#define CBOR_BSTR   2
#define CBOR_TSTR   3
#define CBOR_ARRAY  4
#define CBOR_MAP    5
#define CBOR_SIMPLE 7   /* includes null (0xf6) */

/* Control flag bits (draft RevokedCertsControl). */
#define CTRL_FLAG_SORTED 0x01
#define CTRL_FLAG_REASON 0x02

/**
 * \brief Read one CBOR head: major type, argument, and the offset just past the
 *        head (not the content). Handles immediate + 1/2/4/8-byte arguments.
 * \return 0 on success, -1 on truncation.
 */
static int
cbor_head(const uint8_t *p, const uint8_t *end,
          uint8_t *major, uint64_t *arg, const uint8_t **body)
{
  if(p >= end) {
    return -1;
  }
  uint8_t ib = *p++;
  *major = ib >> 5;
  uint8_t ai = ib & 0x1f;
  uint64_t v = 0;
  if(ai < 24) {
    v = ai;
  } else if(ai == 24) {
    if(p + 1 > end) { return -1; }
    v = *p++;
  } else if(ai == 25) {
    if(p + 2 > end) { return -1; }
    v = ((uint64_t)p[0] << 8) | p[1];
    p += 2;
  } else if(ai == 26) {
    if(p + 4 > end) { return -1; }
    v = ((uint64_t)p[0] << 24) | ((uint64_t)p[1] << 16) |
        ((uint64_t)p[2] << 8) | p[3];
    p += 4;
  } else if(ai == 27) {
    if(p + 8 > end) { return -1; }
    for(int i = 0; i < 8; i++) { v = (v << 8) | p[i]; }
    p += 8;
  } else {
    return -1;    /* reserved / indefinite not supported */
  }
  *major = ib >> 5;
  *arg = v;
  *body = p;
  return 0;
}

/**
 * \brief Advance \p *pp past exactly one complete CBOR item (recursing into
 *        arrays/maps). \return 0 on success, -1 on malformed input.
 */
static int
cbor_skip(const uint8_t **pp, const uint8_t *end)
{
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;
  if(cbor_head(*pp, end, &major, &arg, &body) != 0) {
    return -1;
  }
  switch(major) {
  case CBOR_UINT:
  case CBOR_NINT:
  case CBOR_SIMPLE:
    *pp = body;
    return 0;
  case CBOR_BSTR:
  case CBOR_TSTR:
    if(body + arg > end) { return -1; }
    *pp = body + arg;
    return 0;
  case CBOR_ARRAY:
    *pp = body;
    for(uint64_t i = 0; i < arg; i++) {
      if(cbor_skip(pp, end) != 0) { return -1; }
    }
    return 0;
  case CBOR_MAP:
    *pp = body;
    for(uint64_t i = 0; i < arg * 2; i++) {
      if(cbor_skip(pp, end) != 0) { return -1; }
    }
    return 0;
  default:
    return -1;
  }
}

/* Is the item at p a CBOR null (0xf6)? */
static int
is_null(const uint8_t *p, const uint8_t *end)
{
  return p < end && *p == 0xf6;
}

int
c509_crl_parse(const uint8_t *buf, size_t len, c509_crl_t *crl)
{
  if(buf == NULL || crl == NULL || len == 0) {
    return -1;
  }
  memset(crl, 0, sizeof(*crl));

  const uint8_t *end = buf + len;
  const uint8_t *p = buf;
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;

  /* Outer C509CRL array (11 elements). */
  if(cbor_head(p, end, &major, &arg, &body) != 0 || major != CBOR_ARRAY ||
     arg != 11) {
    return -1;
  }
  p = body;

  /* Skip the first 9 TBS fields: crlType, signatureAlgorithm,
   * authoritySubject, authorityKeyIdentifier, crlNumber, thisUpdate,
   * nextUpdate, baseCrlNumber, crlExtensions. */
  for(int i = 0; i < 9; i++) {
    if(cbor_skip(&p, end) != 0) {
      return -1;
    }
  }

  /* revokedCertsList: null, or an array of 5*groups elements. */
  if(is_null(p, end)) {
    return 0;    /* no revocations */
  }
  if(cbor_head(p, end, &major, &arg, &body) != 0 || major != CBOR_ARRAY ||
     arg == 0 || (arg % 5) != 0) {
    return -1;
  }
  crl->group_count = (uint32_t)(arg / 5);
  p = body;

  /* First group: (issuer, control, extensions, revoked, removed). */
  /* issuer */
  if(cbor_skip(&p, end) != 0) {
    return -1;
  }
  /* control: null, or array(4) = [flags, snLen, dateLen, base_date] */
  if(is_null(p, end)) {
    /* no control -> no revoked entries in this group */
    return 0;
  }
  if(cbor_head(p, end, &major, &arg, &body) != 0 || major != CBOR_ARRAY ||
     arg != 4) {
    return -1;
  }
  p = body;
  uint64_t flags, snlen, dlen, base;
  if(cbor_head(p, end, &major, &flags, &body) != 0 || major != CBOR_UINT) {
    return -1;
  }
  p = body;
  if(cbor_head(p, end, &major, &snlen, &body) != 0 || major != CBOR_UINT) {
    return -1;
  }
  p = body;
  if(cbor_head(p, end, &major, &dlen, &body) != 0 || major != CBOR_UINT) {
    return -1;
  }
  p = body;
  if(cbor_head(p, end, &major, &base, &body) != 0 || major != CBOR_UINT) {
    return -1;
  }
  p = body;

  if(snlen == 0 || snlen > 64) {
    return -1;
  }
  crl->serial_len = (uint32_t)snlen;
  crl->date_len = (uint32_t)dlen;
  crl->sorted = (flags & CTRL_FLAG_SORTED) ? 1 : 0;
  crl->has_reason = (flags & CTRL_FLAG_REASON) ? 1 : 0;
  crl->base_date = base;
  crl->entry_len = (uint32_t)snlen + (uint32_t)dlen + (crl->has_reason ? 1 : 0);

  /* extensions */
  if(cbor_skip(&p, end) != 0) {
    return -1;
  }
  /* revokedCerts: null, or a byte string of fixed-width entries. */
  if(is_null(p, end)) {
    return 0;
  }
  if(cbor_head(p, end, &major, &arg, &body) != 0 || major != CBOR_BSTR) {
    return -1;
  }
  if(body + arg > end) {
    return -1;
  }
  if(crl->entry_len == 0 || (arg % crl->entry_len) != 0) {
    return -1;
  }
  crl->revoked = body;
  crl->revoked_len = (size_t)arg;
  crl->n_entries = (uint32_t)(arg / crl->entry_len);
  return 0;
}

/* Compare a left-padded query serial against entry i's serial (big-endian,
 * fixed width serial_len). Returns <0, 0, >0. */
static int
cmp_serial(const c509_crl_t *crl, uint32_t i,
           const uint8_t *qserial /* already serial_len wide */)
{
  const uint8_t *e = crl->revoked + (size_t)i * crl->entry_len;
  return memcmp(qserial, e, crl->serial_len);
}

/* Find the entry index for a serial, or -1. Fills a serial_len-wide scratch. */
static long
find_index(const c509_crl_t *crl, const uint8_t *serial, size_t serial_len)
{
  if(crl->revoked == NULL || crl->n_entries == 0) {
    return -1;
  }
  if(serial_len > crl->serial_len) {
    return -2;
  }
  uint8_t q[64];
  memset(q, 0, crl->serial_len);
  memcpy(q + (crl->serial_len - serial_len), serial, serial_len);

  if(crl->sorted) {
    long lo = 0, hi = (long)crl->n_entries - 1;
    while(lo <= hi) {
      long mid = lo + (hi - lo) / 2;
      int c = cmp_serial(crl, (uint32_t)mid, q);
      if(c == 0) {
        return mid;
      } else if(c < 0) {
        hi = mid - 1;
      } else {
        lo = mid + 1;
      }
    }
    return -1;
  }
  for(uint32_t i = 0; i < crl->n_entries; i++) {
    if(cmp_serial(crl, i, q) == 0) {
      return (long)i;
    }
  }
  return -1;
}

int
c509_crl_is_revoked(const c509_crl_t *crl,
                    const uint8_t *serial, size_t serial_len)
{
  if(crl == NULL || serial == NULL) {
    return -1;
  }
  long idx = find_index(crl, serial, serial_len);
  if(idx == -2) {
    return -1;    /* serial wider than serial_len */
  }
  return idx >= 0 ? 1 : 0;
}

int
c509_crl_reason(const c509_crl_t *crl,
                const uint8_t *serial, size_t serial_len)
{
  if(crl == NULL || serial == NULL || !crl->has_reason) {
    return -1;
  }
  long idx = find_index(crl, serial, serial_len);
  if(idx < 0) {
    return -1;
  }
  const uint8_t *e = crl->revoked + (size_t)idx * crl->entry_len;
  return e[crl->serial_len + crl->date_len];   /* reason byte follows serial+date */
}
