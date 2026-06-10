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
 *   Implementation of the static trust anchor store for EDHOC C509
 *   certificate chain validation.
 *
 *   This module holds a single, process-wide edhoc_trust_store_t instance
 *   (\c active_store).  It does not own or copy the underlying array of
 *   trust anchors: the caller of edhoc_set_c509_trust_store() is expected
 *   to provide a pointer to storage (e.g. a const array) that remains
 *   valid for the lifetime of the application.  Lookups against this store
 *   (e.g. matching a CA's public key while validating a certificate chain)
 *   are performed by edhoc_c509_validate_chain() in edhoc-cred-c509.c.
 *
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include "edhoc-trust-store.h"
#include <stddef.h>

/* The single, process-wide trust store. Empty (anchors == NULL, count == 0)
 * until edhoc_set_c509_trust_store() is called by the application. */
static edhoc_trust_store_t active_store = { .anchors = NULL, .count = 0 };

/*---------------------------------------------------------------------------*/
/**
 * \brief Register the process-wide C509 trust store.
 *
 * Simply stores the given pointer and count in \c active_store; the
 * array itself is not copied, so it must remain valid for as long as
 * the trust store may be queried (typically for the lifetime of the
 * application).
 *
 * \param anchors  Array of trust anchor public keys.
 * \param count    Number of entries in \p anchors.
 */
void
edhoc_set_c509_trust_store(const cose_key_t *anchors, size_t count)
{
  active_store.anchors = anchors;
  active_store.count   = count;
}
/*---------------------------------------------------------------------------*/
/**
 * \brief Return a pointer to the active trust store.
 *
 * \return A pointer to the process-wide trust store, or NULL if
 *         edhoc_set_c509_trust_store() has not yet been called (or was
 *         called with an empty/NULL array), signalling that no trust
 *         anchors are configured.
 */
const edhoc_trust_store_t *
edhoc_get_c509_trust_store(void)
{
  if(active_store.anchors == NULL || active_store.count == 0) {
    return NULL;
  }
  return &active_store;
}
