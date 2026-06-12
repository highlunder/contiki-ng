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
 *   Minimal RFC 8949 CBOR header/integer writers, shared by the
 *   self-contained c509-csr-build.c and c509-ca.c modules. Header-only
 *   `static` functions so each translation unit gets its own copy with no
 *   link-time symbols — avoids any dependency on os/services/c509/cbor.h or
 *   os/lib/cbor.h (and thus their `cbor_major_type_t` collision).
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_CBOR_WRITER_H
#define C509_CBOR_WRITER_H

#include <stdint.h>
#include <stddef.h>

/* Writes an RFC 8949 initial-byte(+argument) header for major type
 * `major_shifted` (already shifted into bits 5-7) and length/value `len`.
 * Returns 0 on success, -1 if `buffer` (size `size`, current offset
 * `*offset`) has insufficient space. */
static int write_cbor_header(uint8_t *buffer, size_t size, size_t *offset,
                              uint8_t major_shifted, uint64_t len) {
    size_t need;
    if (len < 24) {
        need = 1;
    } else if (len <= 0xFF) {
        need = 2;
    } else if (len <= 0xFFFF) {
        need = 3;
    } else if (len <= 0xFFFFFFFFu) {
        need = 5;
    } else {
        need = 9;
    }
    if (*offset + need > size) return -1;

    if (len < 24) {
        buffer[*offset] = (uint8_t)(major_shifted | len);
    } else if (len <= 0xFF) {
        buffer[*offset] = (uint8_t)(major_shifted | 24);
        buffer[*offset + 1] = (uint8_t)len;
    } else if (len <= 0xFFFF) {
        buffer[*offset] = (uint8_t)(major_shifted | 25);
        buffer[*offset + 1] = (uint8_t)(len >> 8);
        buffer[*offset + 2] = (uint8_t)len;
    } else if (len <= 0xFFFFFFFFu) {
        buffer[*offset] = (uint8_t)(major_shifted | 26);
        for (size_t i = 0; i < 4; i++) buffer[*offset + 1 + i] = (uint8_t)(len >> (24 - 8 * i));
    } else {
        buffer[*offset] = (uint8_t)(major_shifted | 27);
        for (size_t i = 0; i < 8; i++) buffer[*offset + 1 + i] = (uint8_t)(len >> (56 - 8 * i));
    }
    *offset += need;
    return 0;
}

/* Writes a CBOR integer (major type 0 for >= 0, major type 1 for < 0,
 * per RFC 8949 §3.1). */
static int write_cbor_int(uint8_t *buffer, size_t size, size_t *offset, int64_t v) {
    if (v >= 0) {
        return write_cbor_header(buffer, size, offset, 0x00, (uint64_t)v);
    }
    return write_cbor_header(buffer, size, offset, 0x20, (uint64_t)(-(v + 1)));
}

#endif /* C509_CBOR_WRITER_H */
