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
 *   C509 revocation-object signature verification — see c509-rev-verify.h.
 */

#include "c509-rev-verify.h"
#include "c509-cbor-lite.h"
#include "ed25519_verify.h"

int
c509_rev_locate_tbs(const uint8_t *buf, size_t len,
                    const uint8_t **tbs, size_t *tbs_len,
                    const uint8_t **sig, size_t *sig_len)
{
  if(buf == NULL || tbs == NULL || tbs_len == NULL ||
     sig == NULL || sig_len == NULL) {
    return -1;
  }
  const uint8_t *end = buf + len;
  uint8_t major;
  uint64_t n;
  const uint8_t *body;

  if(c509_cbor_head(buf, end, &major, &n, &body) != 0 ||
     major != C509_CBOR_ARRAY || n < 2) {
    return -1;
  }
  const uint8_t *tbs_start = body;

  /* Skip the first N-1 elements (the TBS group). */
  const uint8_t *p = body;
  for(uint64_t i = 0; i + 1 < n; i++) {
    if(c509_cbor_skip(&p, end) != 0) {
      return -1;
    }
  }
  const uint8_t *sig_item = p;

  /* Last element: signatureValue byte string. */
  uint64_t slen;
  const uint8_t *sbody;
  if(c509_cbor_head(sig_item, end, &major, &slen, &sbody) != 0 ||
     major != C509_CBOR_BSTR || sbody + slen > end) {
    return -1;
  }

  *tbs = tbs_start;
  *tbs_len = (size_t)(sig_item - tbs_start);
  *sig = sbody;
  *sig_len = (size_t)slen;
  return 0;
}

int
c509_rev_sig_alg(const uint8_t *buf, size_t len, int64_t *alg_out)
{
  if(buf == NULL || alg_out == NULL) {
    return -1;
  }
  const uint8_t *end = buf + len;
  uint8_t major;
  uint64_t n;
  const uint8_t *body;
  if(c509_cbor_head(buf, end, &major, &n, &body) != 0 ||
     major != C509_CBOR_ARRAY || n < 2) {
    return -1;
  }
  /* element 0 = type/crlType; element 1 = signatureAlgorithm (int). */
  const uint8_t *p = body;
  if(c509_cbor_skip(&p, end) != 0) {          /* skip element 0 */
    return -1;
  }
  uint64_t arg;
  if(c509_cbor_head(p, end, &major, &arg, &body) != 0) {
    return -1;
  }
  if(major == C509_CBOR_UINT) {
    *alg_out = (int64_t)arg;
  } else if(major == C509_CBOR_NINT) {
    *alg_out = -1 - (int64_t)arg;
  } else {
    return -1;
  }
  return 0;
}

int
c509_rev_verify_ed25519(const uint8_t *buf, size_t len, const uint8_t pk[32])
{
  const uint8_t *tbs, *sig;
  size_t tbs_len, sig_len;

  if(c509_rev_locate_tbs(buf, len, &tbs, &tbs_len, &sig, &sig_len) != 0) {
    return -1;
  }
  if(sig_len != 64) {
    return -1;
  }
  return ed25519_verify(pk, sig, tbs, tbs_len) == 0 ? 0 : -1;
}
