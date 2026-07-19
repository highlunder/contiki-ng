/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   Deterministic CBOR write helpers (see ra-cbor.h).
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-cbor.h"
#include <string.h>

int
ra_cbor_head(uint8_t *buf, size_t sz, size_t *off, uint8_t major, uint64_t arg)
{
  uint8_t mt = (uint8_t)(major << 5);
  size_t need;
  if(arg < 24) {
    need = 1;
  } else if(arg <= 0xFF) {
    need = 2;
  } else if(arg <= 0xFFFF) {
    need = 3;
  } else if(arg <= 0xFFFFFFFFu) {
    need = 5;
  } else {
    need = 9;
  }
  if(*off + need > sz) {
    return -1;
  }
  if(arg < 24) {
    buf[*off] = (uint8_t)(mt | arg);
  } else if(arg <= 0xFF) {
    buf[*off] = (uint8_t)(mt | 24);
    buf[*off + 1] = (uint8_t)arg;
  } else if(arg <= 0xFFFF) {
    buf[*off] = (uint8_t)(mt | 25);
    buf[*off + 1] = (uint8_t)(arg >> 8);
    buf[*off + 2] = (uint8_t)arg;
  } else if(arg <= 0xFFFFFFFFu) {
    buf[*off] = (uint8_t)(mt | 26);
    for(int i = 0; i < 4; i++) {
      buf[*off + 1 + i] = (uint8_t)(arg >> (24 - 8 * i));
    }
  } else {
    buf[*off] = (uint8_t)(mt | 27);
    for(int i = 0; i < 8; i++) {
      buf[*off + 1 + i] = (uint8_t)(arg >> (56 - 8 * i));
    }
  }
  *off += need;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_uint(uint8_t *buf, size_t sz, size_t *off, uint64_t v)
{
  return ra_cbor_head(buf, sz, off, 0, v);
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_int(uint8_t *buf, size_t sz, size_t *off, int64_t v)
{
  if(v >= 0) {
    return ra_cbor_head(buf, sz, off, 0, (uint64_t)v);
  }
  return ra_cbor_head(buf, sz, off, 1, (uint64_t)(-(v + 1)));
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_bstr(uint8_t *buf, size_t sz, size_t *off, const uint8_t *b, size_t len)
{
  if(ra_cbor_head(buf, sz, off, 2, len) != 0) {
    return -1;
  }
  if(*off + len > sz) {
    return -1;
  }
  if(len) {
    memcpy(buf + *off, b, len);
  }
  *off += len;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_tstr(uint8_t *buf, size_t sz, size_t *off, const char *s, size_t len)
{
  if(ra_cbor_head(buf, sz, off, 3, len) != 0) {
    return -1;
  }
  if(*off + len > sz) {
    return -1;
  }
  if(len) {
    memcpy(buf + *off, s, len);
  }
  *off += len;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_array(uint8_t *buf, size_t sz, size_t *off, uint64_t n)
{
  return ra_cbor_head(buf, sz, off, 4, n);
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_map(uint8_t *buf, size_t sz, size_t *off, uint64_t n)
{
  return ra_cbor_head(buf, sz, off, 5, n);
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_tag(uint8_t *buf, size_t sz, size_t *off, uint64_t tag)
{
  return ra_cbor_head(buf, sz, off, 6, tag);
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_raw(uint8_t *buf, size_t sz, size_t *off, const uint8_t *b, size_t len)
{
  if(*off + len > sz) {
    return -1;
  }
  if(len) {
    memcpy(buf + *off, b, len);
  }
  *off += len;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_read_head(const uint8_t *p, const uint8_t *end,
                  uint8_t *major, uint64_t *arg, const uint8_t **body)
{
  if(p >= end) {
    return -1;
  }
  uint8_t ib = *p++;
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
    v = ((uint64_t)p[0] << 24) | ((uint64_t)p[1] << 16) | ((uint64_t)p[2] << 8) | p[3];
    p += 4;
  } else if(ai == 27) {
    if(p + 8 > end) { return -1; }
    for(int i = 0; i < 8; i++) { v = (v << 8) | p[i]; }
    p += 8;
  } else {
    return -1; /* reserved / indefinite not supported */
  }
  *major = ib >> 5;
  *arg = v;
  *body = p;
  return 0;
}
/*---------------------------------------------------------------------------*/
int
ra_cbor_read_skip(const uint8_t **pp, const uint8_t *end)
{
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;
  if(ra_cbor_read_head(*pp, end, &major, &arg, &body) != 0) {
    return -1;
  }
  switch(major) {
  case RA_CBOR_UINT:
  case RA_CBOR_NINT:
  case RA_CBOR_SIMPLE:
    *pp = body;
    return 0;
  case RA_CBOR_BSTR:
  case RA_CBOR_TSTR:
    if(body + arg > end) { return -1; }
    *pp = body + arg;
    return 0;
  case RA_CBOR_ARRAY:
    *pp = body;
    for(uint64_t i = 0; i < arg; i++) {
      if(ra_cbor_read_skip(pp, end) != 0) { return -1; }
    }
    return 0;
  case RA_CBOR_MAP:
    *pp = body;
    for(uint64_t i = 0; i < arg * 2; i++) {
      if(ra_cbor_read_skip(pp, end) != 0) { return -1; }
    }
    return 0;
  default:
    return -1;
  }
}
