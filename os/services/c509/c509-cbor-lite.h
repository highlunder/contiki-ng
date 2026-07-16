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
 *   Minimal read-only CBOR walker shared by the self-contained C509 revocation
 *   modules (c509-crl, c509-ocsp, c509-rev-verify). Just enough to read an item
 *   head and skip complete items — definite-length only.
 *
 *   Deliberately NOT os/services/c509/cbor.h: that header's `cbor_major_type_t`
 *   collides with os/lib/cbor.h when both land in one translation unit. This
 *   header defines no such colliding type, so the revocation modules link into
 *   EDHOC/OSCORE/DTLS clients cleanly, like c509-chain / c509-csr-* /
 *   x509-csr-parse.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_CBOR_LITE_H
#define C509_CBOR_LITE_H

#include <stdint.h>
#include <stddef.h>

/* CBOR major types (high 3 bits of the initial byte). */
#define C509_CBOR_UINT   0
#define C509_CBOR_NINT   1
#define C509_CBOR_BSTR   2
#define C509_CBOR_TSTR   3
#define C509_CBOR_ARRAY  4
#define C509_CBOR_MAP    5
#define C509_CBOR_SIMPLE 7   /* includes null (0xf6) */

/**
 * \brief Read one CBOR item head at \p p: major type, argument, and \p body
 *        (the offset just past the head, i.e. the start of content for
 *        strings/arrays, or the next item for uints/simples).
 * \return 0 on success, -1 on truncation / unsupported (indefinite) encoding.
 */
int c509_cbor_head(const uint8_t *p, const uint8_t *end,
                   uint8_t *major, uint64_t *arg, const uint8_t **body);

/**
 * \brief Advance \p *pp past exactly one complete CBOR item (recursing into
 *        arrays/maps). \return 0 on success, -1 on malformed input.
 */
int c509_cbor_skip(const uint8_t **pp, const uint8_t *end);

/** \brief Non-zero iff the item at \p p is CBOR null (0xf6). */
int c509_cbor_is_null(const uint8_t *p, const uint8_t *end);

#endif /* C509_CBOR_LITE_H */
