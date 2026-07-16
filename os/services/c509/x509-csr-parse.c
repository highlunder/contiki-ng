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
 *   Minimal PKCS#10 CertificationRequest DER parser — see x509-csr-parse.h.
 */

#include "x509-csr-parse.h"
#include <string.h>

/* ASN.1 DER tags used here. */
#define TAG_INTEGER      0x02
#define TAG_BIT_STRING   0x03
#define TAG_OID          0x06
#define TAG_UTF8STRING   0x0c
#define TAG_PRINTABLE    0x13
#define TAG_IA5STRING    0x16
#define TAG_SEQUENCE     0x30
#define TAG_SET          0x31
#define TAG_CTX0         0xa0   /* [0] IMPLICIT (attributes) */

/* commonName OID body (2.5.4.3), i.e. the bytes after the OID tag+len. */
static const uint8_t OID_COMMON_NAME[] = { 0x55, 0x04, 0x03 };

/**
 * \brief Reads one DER TLV: returns its tag, content pointer/length, and the
 *        pointer just past the whole TLV. Supports short form and 1/2-byte
 *        long-form lengths (enough for a ~400-byte CSR). Returns 0 on success.
 */
static int
der_tlv(const uint8_t *p, const uint8_t *end,
        uint8_t *tag, const uint8_t **content, size_t *clen,
        const uint8_t **next)
{
  if(p == NULL || p + 2 > end) {
    return -1;
  }
  *tag = p[0];
  size_t l = p[1];
  const uint8_t *c = p + 2;
  if(l & 0x80) {
    int nb = (int)(l & 0x7f);
    if(nb < 1 || nb > 2 || c + nb > end) {
      return -1;
    }
    l = 0;
    for(int i = 0; i < nb; i++) {
      l = (l << 8) | c[i];
    }
    c += nb;
  }
  if(c + l > end) {
    return -1;
  }
  *content = c;
  *clen = l;
  if(next != NULL) {
    *next = c + l;
  }
  return 0;
}

/**
 * \brief Copies a DER INTEGER's magnitude into a fixed 32-byte big-endian
 *        field (strips a leading 0x00 sign byte, left-zero-pads short values).
 */
static int
int_to_32(const uint8_t *c, size_t l, uint8_t *out32)
{
  while(l > 0 && c[0] == 0x00) {
    c++;
    l--;
  }
  if(l > 32) {
    return -1;
  }
  memset(out32, 0, 32);
  memcpy(out32 + (32 - l), c, l);
  return 0;
}

int
x509_csr_parse(const uint8_t *buf, size_t len,
               const uint8_t **subject, size_t *subject_len,
               const uint8_t **pk_key, size_t *pk_key_len,
               const uint8_t **cri_ptr, size_t *cri_len,
               uint8_t *sig_rs)
{
  if(buf == NULL || subject == NULL || subject_len == NULL ||
     pk_key == NULL || pk_key_len == NULL || cri_ptr == NULL ||
     cri_len == NULL || sig_rs == NULL) {
    return -1;
  }

  const uint8_t *end = buf + len;
  uint8_t tag;
  const uint8_t *c, *next;
  size_t cl;

  /* CertificationRequest ::= SEQUENCE { CRI, sigAlg, signature } */
  if(der_tlv(buf, end, &tag, &c, &cl, NULL) != 0 || tag != TAG_SEQUENCE) {
    return -1;
  }
  const uint8_t *cr_end = c + cl;

  /* CertificationRequestInfo — record the whole TLV as the signed bytes. */
  const uint8_t *cri_body;
  size_t cri_body_len;
  if(der_tlv(c, cr_end, &tag, &cri_body, &cri_body_len, &next) != 0 ||
     tag != TAG_SEQUENCE) {
    return -1;
  }
  *cri_ptr = c;              /* from the CRI SEQUENCE tag ... */
  *cri_len = (size_t)(next - c); /* ... through its last content byte */
  const uint8_t *cri_end = cri_body + cri_body_len;
  const uint8_t *after_cri = next;

  /* version INTEGER (0) */
  const uint8_t *q = cri_body;
  if(der_tlv(q, cri_end, &tag, &c, &cl, &next) != 0 || tag != TAG_INTEGER) {
    return -1;
  }
  q = next;

  /* subject Name ::= SEQUENCE { SET { SEQUENCE { OID commonName, value } } } */
  if(der_tlv(q, cri_end, &tag, &c, &cl, &next) != 0 || tag != TAG_SEQUENCE) {
    return -1;
  }
  q = next;
  {
    const uint8_t *rdn_end = c + cl;
    const uint8_t *set_c, *atv_c, *oid_c, *val_c;
    size_t set_l, atv_l, oid_l, val_l;
    if(der_tlv(c, rdn_end, &tag, &set_c, &set_l, NULL) != 0 || tag != TAG_SET) {
      return -1;
    }
    if(der_tlv(set_c, set_c + set_l, &tag, &atv_c, &atv_l, NULL) != 0 ||
       tag != TAG_SEQUENCE) {
      return -1;
    }
    const uint8_t *atv_end = atv_c + atv_l;
    if(der_tlv(atv_c, atv_end, &tag, &oid_c, &oid_l, &next) != 0 ||
       tag != TAG_OID || oid_l != sizeof(OID_COMMON_NAME) ||
       memcmp(oid_c, OID_COMMON_NAME, oid_l) != 0) {
      return -1;
    }
    if(der_tlv(next, atv_end, &tag, &val_c, &val_l, NULL) != 0 ||
       (tag != TAG_UTF8STRING && tag != TAG_PRINTABLE && tag != TAG_IA5STRING)) {
      return -1;
    }
    *subject = val_c;
    *subject_len = val_l;
  }

  /* SubjectPublicKeyInfo ::= SEQUENCE { AlgorithmIdentifier, BIT STRING } */
  if(der_tlv(q, cri_end, &tag, &c, &cl, &next) != 0 || tag != TAG_SEQUENCE) {
    return -1;
  }
  {
    const uint8_t *spki_end = c + cl;
    const uint8_t *alg_c, *bs_c;
    size_t alg_l, bs_l;
    /* skip AlgorithmIdentifier */
    if(der_tlv(c, spki_end, &tag, &alg_c, &alg_l, &next) != 0 ||
       tag != TAG_SEQUENCE) {
      return -1;
    }
    /* subjectPublicKey BIT STRING: content = 00 (unused bits) || 04 X Y */
    if(der_tlv(next, spki_end, &tag, &bs_c, &bs_l, NULL) != 0 ||
       tag != TAG_BIT_STRING || bs_l != 1 + 65 ||
       bs_c[0] != 0x00 || bs_c[1] != 0x04) {
      return -1;
    }
    *pk_key = bs_c + 1;     /* 0x04 || X || Y */
    *pk_key_len = 65;
  }

  /* signatureAlgorithm — skip. */
  if(der_tlv(after_cri, cr_end, &tag, &c, &cl, &next) != 0 ||
     tag != TAG_SEQUENCE) {
    return -1;
  }

  /* signature BIT STRING: content = 00 || SEQUENCE { INTEGER r, INTEGER s } */
  if(der_tlv(next, cr_end, &tag, &c, &cl, NULL) != 0 ||
     tag != TAG_BIT_STRING || cl < 2 || c[0] != 0x00) {
    return -1;
  }
  {
    const uint8_t *sig_seq = c + 1;
    const uint8_t *sig_end = c + cl;
    const uint8_t *seq_c, *r_c, *s_c;
    size_t seq_l, r_l, s_l;
    if(der_tlv(sig_seq, sig_end, &tag, &seq_c, &seq_l, NULL) != 0 ||
       tag != TAG_SEQUENCE) {
      return -1;
    }
    const uint8_t *seq_end = seq_c + seq_l;
    if(der_tlv(seq_c, seq_end, &tag, &r_c, &r_l, &next) != 0 ||
       tag != TAG_INTEGER) {
      return -1;
    }
    if(der_tlv(next, seq_end, &tag, &s_c, &s_l, NULL) != 0 ||
       tag != TAG_INTEGER) {
      return -1;
    }
    if(int_to_32(r_c, r_l, sig_rs) != 0 ||
       int_to_32(s_c, s_l, sig_rs + 32) != 0) {
      return -1;
    }
  }

  return 0;
}
