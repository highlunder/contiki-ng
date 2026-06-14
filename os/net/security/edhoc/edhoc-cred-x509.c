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
 *   X.509 (DER) certificate credential support for EDHOC.
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include "edhoc-cred-x509.h"
#include "edhoc-config.h"
#include "edhoc-error.h"
#include "edhoc-key-storage.h"
#include "edhoc-trust-store.h"
#include "lib/cbor.h"
#include "lib/sha-256.h"
#include "os/net/security/micro-ecc/uECC.h"
#include <string.h>

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "EDHOC-X509"
#define LOG_LEVEL LOG_LEVEL_INFO

/* DER tags used while walking the certificate structure. */
#define DER_TAG_INTEGER     0x02
#define DER_TAG_BIT_STRING  0x03
#define DER_TAG_SEQUENCE    0x30
#define DER_TAG_CONTEXT_0   0xA0  /* [0] EXPLICIT version, inside TBSCertificate */

/*---------------------------------------------------------------------------*/
/* Reads one DER TLV header at *pos (short-form or 1/2-byte long-form
 * length). On success, advances *pos to the start of the content and
 * returns the tag and content length; the caller can compute the position
 * after this TLV as (*pos + content_len). */
static int
der_read_tlv(const uint8_t *buf, size_t len, size_t *pos,
              uint8_t *tag_out, size_t *content_len_out)
{
  if(*pos >= len) {
    return -1;
  }
  uint8_t tag = buf[*pos];
  size_t p = *pos + 1;
  if(p >= len) {
    return -1;
  }
  uint8_t l0 = buf[p++];
  size_t clen;
  if(l0 & 0x80) {
    uint8_t nbytes = l0 & 0x7f;
    if(nbytes == 0 || nbytes > 2 || p + nbytes > len) {
      return -1;
    }
    clen = 0;
    for(uint8_t i = 0; i < nbytes; i++) {
      clen = (clen << 8) | buf[p++];
    }
  } else {
    clen = l0;
  }
  if(p + clen > len) {
    return -1;
  }
  *tag_out = tag;
  *content_len_out = clen;
  *pos = p;
  return 0;
}
/*---------------------------------------------------------------------------*/
/* Converts a DER INTEGER's content (big-endian, possibly with a leading
 * 0x00 sign-padding byte) to a fixed-size big-endian buffer of
 * ECC_KEY_LEN bytes, left-padding with zeros if shorter. */
static void
der_int_to_fixed(const uint8_t *src, size_t src_len, uint8_t *out)
{
  memset(out, 0, ECC_KEY_LEN);
  while(src_len > ECC_KEY_LEN && src[0] == 0x00) {
    src++;
    src_len--;
  }
  if(src_len > ECC_KEY_LEN) {
    src_len = ECC_KEY_LEN;
  }
  memcpy(out + (ECC_KEY_LEN - src_len), src, src_len);
}
/*---------------------------------------------------------------------------*/
/* Walks down to SubjectPublicKeyInfo and returns the offset/length of the
 * raw EC point (the content of the subjectPublicKey BIT STRING, including
 * its leading "0 unused bits" byte and 0x04 uncompressed-point marker).
 * Also (optionally) returns the byte range of the TBSCertificate TLV
 * (tbs_off/tbs_len, tag+length+content) and of the signatureValue BIT
 * STRING content (sig_bs_off/sig_bs_len). */
static int
x509_parse(const uint8_t *der, size_t der_len,
            size_t *spki_point_off, size_t *spki_point_len,
            size_t *tbs_off, size_t *tbs_len,
            size_t *sig_bs_off, size_t *sig_bs_len)
{
  uint8_t tag;
  size_t clen;
  size_t pos = 0;

  /* Certificate ::= SEQUENCE */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  size_t cert_pos = pos; /* start of Certificate content */

  /* tbsCertificate ::= SEQUENCE */
  size_t tbs_tlv_start = cert_pos;
  pos = cert_pos;
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  size_t tbs_content_off = pos;
  size_t tbs_tlv_end = pos + clen;
  cert_pos = tbs_tlv_end;
  if(tbs_off) {
    *tbs_off = tbs_tlv_start;
  }
  if(tbs_len) {
    *tbs_len = tbs_tlv_end - tbs_tlv_start;
  }

  /* Walk the TBSCertificate fields to find subjectPublicKeyInfo. */
  pos = tbs_content_off;

  /* version [0] EXPLICIT (optional) */
  size_t save = pos;
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0) {
    return -1;
  }
  if(tag == DER_TAG_CONTEXT_0) {
    pos = pos + clen; /* skip version, advance to serialNumber */
  } else {
    pos = save; /* not present: this TLV was serialNumber */
  }

  /* serialNumber INTEGER */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_INTEGER) {
    return -1;
  }
  pos += clen;

  /* signature AlgorithmIdentifier SEQUENCE */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  pos += clen;

  /* issuer Name SEQUENCE */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  pos += clen;

  /* validity SEQUENCE */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  pos += clen;

  /* subject Name SEQUENCE */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  pos += clen;

  /* subjectPublicKeyInfo SEQUENCE */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  size_t spki_pos = pos;

  /* algorithm AlgorithmIdentifier SEQUENCE — skip */
  if(der_read_tlv(der, der_len, &spki_pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  spki_pos += clen;

  /* subjectPublicKey BIT STRING */
  if(der_read_tlv(der, der_len, &spki_pos, &tag, &clen) != 0 || tag != DER_TAG_BIT_STRING) {
    return -1;
  }
  if(spki_point_off) {
    *spki_point_off = spki_pos;
  }
  if(spki_point_len) {
    *spki_point_len = clen;
  }

  if(!sig_bs_off || !sig_bs_len) {
    return 0;
  }

  /* signatureAlgorithm AlgorithmIdentifier SEQUENCE — skip (sibling of
   * tbsCertificate inside the outer Certificate SEQUENCE). */
  pos = cert_pos;
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    return -1;
  }
  pos += clen;

  /* signatureValue BIT STRING */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_BIT_STRING) {
    return -1;
  }
  *sig_bs_off = pos;
  *sig_bs_len = clen;
  return 0;
}
/*---------------------------------------------------------------------------*/
size_t
edhoc_x509_generate_cred_x(const cose_key_t *key, uint8_t *out, size_t out_sz)
{
  if(key == NULL || key->c509_data == NULL || key->c509_len == 0) {
    LOG_ERR("generate_cred_x: no DER data in key\n");
    return 0;
  }
  if(key->c509_len > out_sz) {
    LOG_ERR("generate_cred_x: output buffer too small (%zu < %zu)\n",
            out_sz, key->c509_len);
    return 0;
  }
  memcpy(out, key->c509_data, key->c509_len);
  LOG_DBG("CRED_x: %zu bytes of X.509 DER\n", key->c509_len);
  return key->c509_len;
}
/*---------------------------------------------------------------------------*/
size_t
edhoc_x509_generate_id_cred_x5chain(const cose_key_t *key,
                                     uint8_t *out, size_t out_sz)
{
  if(key == NULL || key->c509_data == NULL || key->c509_len == 0) {
    LOG_ERR("generate_id_cred_x5chain: no DER data\n");
    return 0;
  }

  /* Build {33: h'<DER cert bytes>'}
   *   CBOR map(1)
   *     key:   uint 33
   *     value: bstr <X.509 DER cert>
   *
   * Chain case: if c509_data already holds a CBOR array of cert byte
   * strings (chain-length >= 1, [bstr<leaf>, bstr<issuer>, ...]; major
   * type 4), write it verbatim as the map value instead of wrapping it
   * in an outer bstr — i.e. {33: [bstr, bstr, ...]}, mirroring
   * edhoc_c509_generate_id_cred_c5c()'s chain handling.
   */
  cbor_writer_state_t w;
  cbor_init_writer(&w, out, out_sz);
  cbor_open_map(&w);
  cbor_write_unsigned(&w, COSE_HEADER_LABEL_X5CHAIN);
  if((key->c509_data[0] >> 5) == 4) {
    cbor_write_object(&w, key->c509_data, key->c509_len);
  } else {
    cbor_write_data(&w, key->c509_data, key->c509_len);
  }
  cbor_close_map(&w);

  size_t written = cbor_end_writer(&w);
  LOG_DBG("ID_CRED_x (x5chain): %zu bytes\n", written);
  return written;
}
/*---------------------------------------------------------------------------*/
edhoc_error_t
edhoc_x509_extract_pub_key(const uint8_t *der, size_t der_len,
                            cose_key_t *key_out)
{
  if(der == NULL || der_len == 0 || key_out == NULL) {
    return EDHOC_ERR_NULL_POINTER;
  }

  size_t point_off, point_len;
  if(x509_parse(der, der_len, &point_off, &point_len,
                 NULL, NULL, NULL, NULL) != 0) {
    LOG_ERR("extract_pub_key: failed to parse DER structure\n");
    return EDHOC_ERR_CREDENTIAL_NOT_FOUND;
  }

  /* Content: [0x00 unused bits][0x04 uncompressed marker][X 32][Y 32] */
  if(point_len != 1 + 1 + 2 * ECC_KEY_LEN ||
     der[point_off] != 0x00 || der[point_off + 1] != 0x04) {
    LOG_ERR("extract_pub_key: unexpected SubjectPublicKey format (len=%zu)\n",
            point_len);
    return EDHOC_ERR_CREDENTIAL_NOT_FOUND;
  }

  memset(key_out, 0, sizeof(*key_out));
  key_out->kty = 2; /* EC2 */
  key_out->crv = 1; /* P-256 */
  memcpy(key_out->ecc.pub.x, der + point_off + 2, ECC_KEY_LEN);
  memcpy(key_out->ecc.pub.y, der + point_off + 2 + ECC_KEY_LEN, ECC_KEY_LEN);

  LOG_DBG("extract_pub_key: P-256 key extracted from X.509 DER\n");
  return EDHOC_SUCCESS;
}
/*---------------------------------------------------------------------------*/
/* Verify an X.509 DER cert's ECDSA-P256 signature (signatureValue, over
 * SHA-256 of the TBSCertificate DER bytes) against the given signer's
 * public key. Returns 1 if valid, 0 otherwise. Shared by
 * edhoc_x509_validate_self_signed() (signer == the cert's own embedded key)
 * and edhoc_x509_validate_chain() (signer == the issuer's key, or a trust
 * anchor's key). */
static int
x509_verify_signature(const uint8_t *der, size_t der_len,
                       const cose_key_t *signer_pk)
{
  size_t tbs_off, tbs_len, sig_bs_off, sig_bs_len;
  if(x509_parse(der, der_len, NULL, NULL,
                 &tbs_off, &tbs_len, &sig_bs_off, &sig_bs_len) != 0) {
    LOG_ERR("verify_signature: failed to parse DER structure\n");
    return 0;
  }

  /* signatureValue content: [0x00 unused bits][SEQUENCE { INTEGER r, INTEGER s }] */
  if(sig_bs_len < 1 || der[sig_bs_off] != 0x00) {
    LOG_ERR("verify_signature: unexpected signatureValue format\n");
    return 0;
  }
  size_t pos = sig_bs_off + 1;
  uint8_t tag;
  size_t clen;
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_SEQUENCE) {
    LOG_ERR("verify_signature: bad ECDSA-Sig-Value SEQUENCE\n");
    return 0;
  }

  /* INTEGER r */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_INTEGER) {
    LOG_ERR("verify_signature: bad signature r\n");
    return 0;
  }
  uint8_t r[ECC_KEY_LEN];
  der_int_to_fixed(der + pos, clen, r);
  pos += clen;

  /* INTEGER s */
  if(der_read_tlv(der, der_len, &pos, &tag, &clen) != 0 || tag != DER_TAG_INTEGER) {
    LOG_ERR("verify_signature: bad signature s\n");
    return 0;
  }
  uint8_t s[ECC_KEY_LEN];
  der_int_to_fixed(der + pos, clen, s);

  uint8_t sig[2 * ECC_KEY_LEN];
  memcpy(sig, r, ECC_KEY_LEN);
  memcpy(sig + ECC_KEY_LEN, s, ECC_KEY_LEN);

  uint8_t hash[SHA_256_DIGEST_LENGTH];
  SHA_256.hash(der + tbs_off, tbs_len, hash);

  uint8_t pub_xy[2 * ECC_KEY_LEN];
  memcpy(pub_xy,               signer_pk->ecc.pub.x, ECC_KEY_LEN);
  memcpy(pub_xy + ECC_KEY_LEN, signer_pk->ecc.pub.y, ECC_KEY_LEN);

  return uECC_verify(pub_xy, hash, sizeof(hash), sig, uECC_secp256r1());
}
/*---------------------------------------------------------------------------*/
edhoc_error_t
edhoc_x509_validate_self_signed(const uint8_t *der, size_t der_len,
                                 void *app_ctx)
{
  (void)app_ctx;

  if(der == NULL || der_len == 0) {
    return EDHOC_ERR_NULL_POINTER;
  }

  cose_key_t pk;
  if(edhoc_x509_extract_pub_key(der, der_len, &pk) != EDHOC_SUCCESS) {
    LOG_ERR("validate_self_signed: cannot extract public key\n");
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  if(!x509_verify_signature(der, der_len, &pk)) {
    LOG_ERR("validate_self_signed: ECDSA signature verification FAILED\n");
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  LOG_INFO("validate_self_signed: X.509 DER cert OK (self-signed)\n");
  return EDHOC_SUCCESS;
}
/*---------------------------------------------------------------------------*/
/* Maximum chain length (number of certs in an x5chain CRED_x array)
 * supported by edhoc_x509_validate_chain(). Mirrors C509_CHAIN_MAX_CERTS in
 * edhoc-cred-c509.c. */
#define X509_CHAIN_MAX_CERTS 4

/* Verify cert[n-1] (top of chain) against every trust anchor in store,
 * accepting it as soon as one anchor's public key verifies it. Mirrors
 * c509_verify_cert_against_trust_store() in edhoc-cred-c509.c. */
static int
x509_verify_cert_against_trust_store(const uint8_t *der, size_t der_len,
                                      const edhoc_trust_store_t *store)
{
  for(size_t i = 0; i < store->count; i++) {
    if(x509_verify_signature(der, der_len, &store->anchors[i])) {
      LOG_INFO("validate_chain: cert verified by trust anchor %zu\n", i);
      return 1;
    }
  }
  return 0;
}
/*---------------------------------------------------------------------------*/
/*
 * x5chain CRED_x for chain-length >= 1 is a CBOR array of cert byte strings:
 * [bstr<leaf>, bstr<issuer_1>, ..., bstr<issuer_N>] (major type 4, mirroring
 * edhoc_c509_validate_chain()'s c5c chain-array handling). Each cert[i]
 * (i < n-1) must be signed by cert[i+1]'s embedded public key; the last
 * (most-root) cert must be verified by a trust anchor registered via
 * edhoc_set_c509_trust_store() (the trust-store API is cert-encoding-
 * agnostic — it stores public keys, not C509-specific data).
 *
 * A single DER cert (major type != 4, chain-length 0) falls back to
 * edhoc_x509_validate_self_signed(), so this function can be used as the
 * validator for both chain-length-0 and chain-length>=1 deployments.
 */
edhoc_error_t
edhoc_x509_validate_chain(const uint8_t *der, size_t der_len, void *app_ctx)
{
  if(der == NULL || der_len == 0) {
    return EDHOC_ERR_NULL_POINTER;
  }

  if((der[0] >> 5) != 4) {
    return edhoc_x509_validate_self_signed(der, der_len, app_ctx);
  }

  const edhoc_trust_store_t *store = edhoc_get_c509_trust_store();
  if(store == NULL) {
    LOG_ERR("validate_chain: trust store not set\n");
    return EDHOC_ERR_NULL_POINTER;
  }

  cbor_reader_state_t r;
  cbor_init_reader(&r, der, der_len);
  size_t n = cbor_read_array(&r);
  if(n == SIZE_MAX || n < 1 || n > X509_CHAIN_MAX_CERTS) {
    LOG_ERR("validate_chain: unsupported chain length (%zu)\n", n);
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  const uint8_t *certs[X509_CHAIN_MAX_CERTS];
  size_t cert_lens[X509_CHAIN_MAX_CERTS];
  for(size_t i = 0; i < n; i++) {
    certs[i] = cbor_read_data(&r, &cert_lens[i]);
    if(certs[i] == NULL) {
      LOG_ERR("validate_chain: chain element %zu malformed\n", i);
      return EDHOC_ERR_CERTIFICATE_REJECTED;
    }
  }

  /* Structural check on the leaf — its public key must be extractable (the
   * EDHOC stack uses it separately for the auth signature/MAC). */
  cose_key_t leaf_pk;
  if(edhoc_x509_extract_pub_key(certs[0], cert_lens[0], &leaf_pk) != EDHOC_SUCCESS) {
    LOG_ERR("validate_chain: cannot extract leaf public key\n");
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  for(size_t i = 0; i + 1 < n; i++) {
    cose_key_t issuer_pk;
    if(edhoc_x509_extract_pub_key(certs[i + 1], cert_lens[i + 1], &issuer_pk) != EDHOC_SUCCESS) {
      LOG_ERR("validate_chain: cannot extract issuer public key (chain[%zu])\n", i + 1);
      return EDHOC_ERR_CERTIFICATE_REJECTED;
    }
    if(!x509_verify_signature(certs[i], cert_lens[i], &issuer_pk)) {
      LOG_ERR("validate_chain: chain link %zu -> %zu signature invalid\n", i, i + 1);
      return EDHOC_ERR_CERTIFICATE_REJECTED;
    }
  }

  if(!x509_verify_cert_against_trust_store(certs[n - 1], cert_lens[n - 1], store)) {
    LOG_ERR("validate_chain: top-of-chain cert not verified by any trust anchor\n");
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  LOG_INFO("validate_chain: chain of %zu certs verified OK\n", n);
  return EDHOC_SUCCESS;
}
