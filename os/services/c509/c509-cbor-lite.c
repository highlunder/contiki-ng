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
 *   Minimal read-only CBOR walker — see c509-cbor-lite.h.
 */

#include "c509-cbor-lite.h"

int
c509_cbor_head(const uint8_t *p, const uint8_t *end,
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

int
c509_cbor_skip(const uint8_t **pp, const uint8_t *end)
{
  uint8_t major;
  uint64_t arg;
  const uint8_t *body;
  if(c509_cbor_head(*pp, end, &major, &arg, &body) != 0) {
    return -1;
  }
  switch(major) {
  case C509_CBOR_UINT:
  case C509_CBOR_NINT:
  case C509_CBOR_SIMPLE:
    *pp = body;
    return 0;
  case C509_CBOR_BSTR:
  case C509_CBOR_TSTR:
    if(body + arg > end) { return -1; }
    *pp = body + arg;
    return 0;
  case C509_CBOR_ARRAY:
    *pp = body;
    for(uint64_t i = 0; i < arg; i++) {
      if(c509_cbor_skip(pp, end) != 0) { return -1; }
    }
    return 0;
  case C509_CBOR_MAP:
    *pp = body;
    for(uint64_t i = 0; i < arg * 2; i++) {
      if(c509_cbor_skip(pp, end) != 0) { return -1; }
    }
    return 0;
  default:
    return -1;
  }
}

int
c509_cbor_is_null(const uint8_t *p, const uint8_t *end)
{
  return p < end && *p == 0xf6;
}
