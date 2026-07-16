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
#include "c509-cbor-lite.h"
#include <string.h>

/* Control flag bits (draft RevokedCertsControl). */
#define CTRL_FLAG_SORTED 0x01
#define CTRL_FLAG_REASON 0x02

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
  if(c509_cbor_head(p, end, &major, &arg, &body) != 0 || major != C509_CBOR_ARRAY ||
     arg != 11) {
    return -1;
  }
  p = body;

  /* Skip the first 9 TBS fields: crlType, signatureAlgorithm,
   * authoritySubject, authorityKeyIdentifier, crlNumber, thisUpdate,
   * nextUpdate, baseCrlNumber, crlExtensions. */
  for(int i = 0; i < 9; i++) {
    if(c509_cbor_skip(&p, end) != 0) {
      return -1;
    }
  }

  /* revokedCertsList: null, or an array of 5*groups elements. */
  if(c509_cbor_is_null(p, end)) {
    return 0;    /* no revocations */
  }
  if(c509_cbor_head(p, end, &major, &arg, &body) != 0 || major != C509_CBOR_ARRAY ||
     arg == 0 || (arg % 5) != 0) {
    return -1;
  }
  crl->group_count = (uint32_t)(arg / 5);
  p = body;

  /* First group: (issuer, control, extensions, revoked, removed). */
  /* issuer */
  if(c509_cbor_skip(&p, end) != 0) {
    return -1;
  }
  /* control: null, or array(4) = [flags, snLen, dateLen, base_date] */
  if(c509_cbor_is_null(p, end)) {
    /* no control -> no revoked entries in this group */
    return 0;
  }
  if(c509_cbor_head(p, end, &major, &arg, &body) != 0 || major != C509_CBOR_ARRAY ||
     arg != 4) {
    return -1;
  }
  p = body;
  uint64_t flags, snlen, dlen, base;
  if(c509_cbor_head(p, end, &major, &flags, &body) != 0 || major != C509_CBOR_UINT) {
    return -1;
  }
  p = body;
  if(c509_cbor_head(p, end, &major, &snlen, &body) != 0 || major != C509_CBOR_UINT) {
    return -1;
  }
  p = body;
  if(c509_cbor_head(p, end, &major, &dlen, &body) != 0 || major != C509_CBOR_UINT) {
    return -1;
  }
  p = body;
  if(c509_cbor_head(p, end, &major, &base, &body) != 0 || major != C509_CBOR_UINT) {
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
  if(c509_cbor_skip(&p, end) != 0) {
    return -1;
  }
  /* revokedCerts: null, or a byte string of fixed-width entries. */
  if(c509_cbor_is_null(p, end)) {
    return 0;
  }
  if(c509_cbor_head(p, end, &major, &arg, &body) != 0 || major != C509_CBOR_BSTR) {
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

int
c509_cert_serial(const uint8_t *cert, size_t cert_len,
                 const uint8_t **serial, size_t *serial_len)
{
  if(cert == NULL || serial == NULL || serial_len == NULL) {
    return -1;
  }
  const uint8_t *end = cert + cert_len;
  uint8_t major;
  uint64_t n;
  const uint8_t *body;
  /* C509 certificate = flat array; element 0 = type, element 1 = serialNumber. */
  if(c509_cbor_head(cert, end, &major, &n, &body) != 0 ||
     major != C509_CBOR_ARRAY || n < 2) {
    return -1;
  }
  const uint8_t *p = body;
  if(c509_cbor_skip(&p, end) != 0) {    /* skip type */
    return -1;
  }
  uint64_t slen;
  if(c509_cbor_head(p, end, &major, &slen, &body) != 0 ||
     major != C509_CBOR_BSTR || body + slen > end) {
    return -1;
  }
  *serial = body;
  *serial_len = (size_t)slen;
  return 0;
}

int
c509_crl_is_cert_revoked(const uint8_t *cert, size_t cert_len,
                         const c509_crl_t *crl)
{
  const uint8_t *serial;
  size_t serial_len;
  if(c509_cert_serial(cert, cert_len, &serial, &serial_len) != 0) {
    return -1;
  }
  return c509_crl_is_revoked(crl, serial, serial_len);
}
