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
 *   CertificateChain CBOR encode/decode: `[+ bstr]`, where each byte
 *   string is a complete encoded C509 certificate (Type 0-3).
 *
 *   This is the wire format used by the `/crts` (cacerts) enrollment
 *   resource: the server returns its CA chain as a CertificateChain, and
 *   the client decodes each element and validates it (e.g. via
 *   edhoc_c509_validate_chain()).
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef C509_CHAIN_H
#define C509_CHAIN_H

#include <stdint.h>
#include <stddef.h>

/**
 * \brief A view (pointer + length) onto one C509 certificate's bytes.
 *
 * Decoding does not copy: `ptr` points into the CBOR input buffer.
 */
typedef struct {
  const uint8_t *ptr;
  size_t len;
} c509_chain_entry_t;

/**
 * \brief Encode a CertificateChain (`[+ bstr]`) from an array of cert
 * byte strings.
 *
 * \param buffer      Output buffer.
 * \param buffer_size Size of \p buffer in bytes.
 * \param certs       Array of certificate byte strings to encode, in
 *                     order (first entry is conventionally the leaf).
 * \param n_certs     Number of entries in \p certs (must be >= 1).
 *
 * \return Number of bytes written to \p buffer, or 0 on error (e.g.
 *         buffer too small).
 */
size_t c509_chain_encode(uint8_t *buffer, size_t buffer_size,
                          const c509_chain_entry_t *certs, size_t n_certs);

/**
 * \brief Decode a CertificateChain (`[+ bstr]`) into an array of
 * zero-copy entries.
 *
 * \param cbor      CBOR-encoded CertificateChain.
 * \param cbor_len  Length of \p cbor in bytes.
 * \param out_certs Output array, filled with pointers into \p cbor.
 * \param max_certs Capacity of \p out_certs.
 * \param out_n     Set to the number of decoded entries on success.
 *
 * \return 0 on success, -1 on error (malformed CBOR, not an array of
 *         byte strings, or more than \p max_certs entries).
 */
int c509_chain_decode(const uint8_t *cbor, size_t cbor_len,
                       c509_chain_entry_t *out_certs, size_t max_certs,
                       size_t *out_n);

#endif /* C509_CHAIN_H */
