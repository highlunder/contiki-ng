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

#include "c509-chain.h"
#include <string.h>

/*
 * Deliberately self-contained: implements just enough RFC 8949 (array of
 * byte strings) encode/decode without depending on either CBOR library in
 * the tree. os/lib/cbor.c and os/services/c509/cbor.c both compile to
 * "cbor.o" and are mutually exclusive within a single module/link, and
 * pulling in the os/services/c509 module (for its decoder) would shadow
 * the os/lib writer that EDHOC relies on. Keeping this file dependency-free
 * lets it be added to any application (just add c509-chain.c to
 * CONTIKI_SOURCEFILES and os/services/c509 to SOURCEDIRS) regardless of
 * which CBOR implementation that application's other modules pull in.
 */

/* Writes an RFC 8949 initial-byte(+argument) header for major type
 * `major_shifted` (already shifted into bits 5-7) and length/value `len`.
 * Returns the number of bytes written, or 0 if `buffer` (size `size`,
 * current offset `*offset`) has insufficient space. */
static size_t
write_cbor_header(uint8_t *buffer, size_t size, size_t *offset,
                   uint8_t major_shifted, uint64_t len)
{
  size_t need;
  size_t i;

  if(len < 24) {
    need = 1;
  } else if(len <= 0xFF) {
    need = 2;
  } else if(len <= 0xFFFF) {
    need = 4;
  } else if(len <= 0xFFFFFFFFu) {
    need = 5;
  } else {
    need = 9;
  }

  if(*offset + need > size) {
    return 0;
  }

  if(len < 24) {
    buffer[*offset] = (uint8_t)(major_shifted | len);
  } else if(len <= 0xFF) {
    buffer[*offset] = (uint8_t)(major_shifted | 24);
    buffer[*offset + 1] = (uint8_t)len;
  } else if(len <= 0xFFFF) {
    buffer[*offset] = (uint8_t)(major_shifted | 25);
    buffer[*offset + 1] = (uint8_t)(len >> 8);
    buffer[*offset + 2] = (uint8_t)len;
  } else if(len <= 0xFFFFFFFFu) {
    buffer[*offset] = (uint8_t)(major_shifted | 26);
    for(i = 0; i < 4; i++) {
      buffer[*offset + 1 + i] = (uint8_t)(len >> (24 - 8 * i));
    }
  } else {
    buffer[*offset] = (uint8_t)(major_shifted | 27);
    for(i = 0; i < 8; i++) {
      buffer[*offset + 1 + i] = (uint8_t)(len >> (56 - 8 * i));
    }
  }

  *offset += need;
  return need;
}
/*---------------------------------------------------------------------------*/
/* Reads an RFC 8949 initial-byte(+argument) header, checking that the major
 * type matches `expect_major` (0x00, 0x40, 0x80, ... i.e. already shifted
 * into bits 5-7). On success returns 0, advances *offset past the header,
 * and sets *len to the decoded length/value. Returns -1 on error. */
static int
read_cbor_header(const uint8_t *cbor, size_t cbor_len, size_t *offset,
                  uint8_t expect_major, uint64_t *len)
{
  uint8_t initial;
  uint8_t info;
  size_t i;

  if(*offset >= cbor_len) {
    return -1;
  }
  initial = cbor[*offset];
  if((initial & 0xE0) != expect_major) {
    return -1;
  }
  info = initial & 0x1F;
  (*offset)++;

  if(info < 24) {
    *len = info;
    return 0;
  }

  switch(info) {
  case 24: i = 1; break;
  case 25: i = 2; break;
  case 26: i = 4; break;
  case 27: i = 8; break;
  default: return -1; /* indefinite length / reserved: unsupported */
  }

  if(*offset + i > cbor_len) {
    return -1;
  }

  *len = 0;
  while(i-- > 0) {
    *len = (*len << 8) | cbor[*offset];
    (*offset)++;
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
size_t
c509_chain_encode(uint8_t *buffer, size_t buffer_size,
                   const c509_chain_entry_t *certs, size_t n_certs)
{
  size_t offset = 0;
  size_t i;

  if(certs == NULL || n_certs == 0) {
    return 0;
  }

  /* Array header: major type 4 (0x80), n_certs elements. */
  if(write_cbor_header(buffer, buffer_size, &offset, 0x80, n_certs) == 0) {
    return 0;
  }

  for(i = 0; i < n_certs; i++) {
    /* Byte-string header: major type 2 (0x40), entry length. */
    if(write_cbor_header(buffer, buffer_size, &offset, 0x40,
                          certs[i].len) == 0) {
      return 0;
    }
    if(offset + certs[i].len > buffer_size) {
      return 0;
    }
    memcpy(buffer + offset, certs[i].ptr, certs[i].len);
    offset += certs[i].len;
  }

  return offset;
}
/*---------------------------------------------------------------------------*/
int
c509_chain_decode(const uint8_t *cbor, size_t cbor_len,
                   c509_chain_entry_t *out_certs, size_t max_certs,
                   size_t *out_n)
{
  size_t offset = 0;
  uint64_t n;
  uint64_t i;

  if(cbor == NULL || out_certs == NULL || out_n == NULL) {
    return -1;
  }

  if(read_cbor_header(cbor, cbor_len, &offset, 0x80, &n) != 0) {
    return -1;
  }
  if(n == 0 || n > max_certs) {
    return -1;
  }

  for(i = 0; i < n; i++) {
    uint64_t entry_len;
    if(read_cbor_header(cbor, cbor_len, &offset, 0x40, &entry_len) != 0) {
      return -1;
    }
    if(offset + entry_len > cbor_len) {
      return -1;
    }
    out_certs[i].ptr = cbor + offset;
    out_certs[i].len = (size_t)entry_len;
    offset += (size_t)entry_len;
  }

  *out_n = (size_t)n;
  return 0;
}
