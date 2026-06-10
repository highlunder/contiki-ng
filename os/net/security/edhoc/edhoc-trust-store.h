/*
 * Copyright (c) 2024, RISE Research Institutes of Sweden AB
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
 *   Static trust anchor store for EDHOC C509 certificate chain validation.
 *
 *   Provides a process-wide list of trusted CA public keys.  Applications
 *   call edhoc_set_c509_trust_store() once at startup, then pass
 *   edhoc_c509_validate_chain as the validator to edhoc_set_cert_validator().
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#ifndef EDHOC_TRUST_STORE_H_
#define EDHOC_TRUST_STORE_H_

#include "edhoc-key-storage.h"
#include <stddef.h>

/**
 * \brief A set of trust anchor entries (CA public keys).
 *
 * Only the ecc.pub.x and ecc.pub.y fields of each cose_key_t are used;
 * the private key fields are ignored.
 */
typedef struct {
  const cose_key_t *anchors; /**< Pointer to array of trust anchor entries. */
  size_t count;              /**< Number of entries in the array.           */
} edhoc_trust_store_t;

/**
 * \brief Register the process-wide C509 trust store.
 *
 * Must be called before edhoc_client_run() or the server start.
 * The caller retains ownership of \p anchors — the pointer is stored
 * but the array is not copied.
 *
 * \param anchors  Array of trust anchor public keys.
 * \param count    Number of entries.
 */
void edhoc_set_c509_trust_store(const cose_key_t *anchors, size_t count);

/**
 * \brief Return a pointer to the active trust store.
 *
 * Returns NULL if edhoc_set_c509_trust_store() has not been called.
 */
const edhoc_trust_store_t *edhoc_get_c509_trust_store(void);

#endif /* EDHOC_TRUST_STORE_H_ */
