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
 *   ECDSA-secp256r1-SHA256 verification path for C509 revocation objects.
 *   Split from c509-rev-verify.c (which is Ed25519-only + the crypto-free TBS
 *   locator, and can be host-tested with a stubbed Ed25519) so the micro-ecc /
 *   SHA-256 dependency stays in its own translation unit — mirroring how the
 *   enrollment PoP path reuses uECC for ECDSA-P256.
 */

#include "c509-rev-verify.h"
#include "lib/sha-256.h"
#include "os/net/security/micro-ecc/uECC.h"

int
c509_rev_verify_ecdsa_p256(const uint8_t *buf, size_t len,
                           const uint8_t *pubkey, size_t pubkey_len)
{
  const uint8_t *tbs, *sig;
  size_t tbs_len, sig_len;
  const uint8_t *pk;

  if(pubkey == NULL) {
    return -1;
  }
  /* Accept 65-byte uncompressed (0x04||X||Y) or bare 64-byte X||Y. */
  if(pubkey_len == 65 && pubkey[0] == 0x04) {
    pk = pubkey + 1;
  } else if(pubkey_len == 64) {
    pk = pubkey;
  } else {
    return -1;   /* compressed points not handled here */
  }

  if(c509_rev_locate_tbs(buf, len, &tbs, &tbs_len, &sig, &sig_len) != 0) {
    return -1;
  }
  if(sig_len != 64) {
    return -1;   /* r||s for secp256r1 */
  }

  uint8_t hash[32];
  sha_256_hash(tbs, tbs_len, hash);
  return uECC_verify(pk, hash, sizeof(hash), sig, uECC_secp256r1()) ? 0 : -1;
}
