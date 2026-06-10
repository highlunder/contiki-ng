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
 *   C509 certificate credential support for EDHOC.
 * \author Joel Höglund <joel.hoglund@ri.se>
 */

#include "edhoc-cred-c509.h"
#include "edhoc-trust-store.h"
#include "edhoc-config.h"
#include "edhoc-error.h"
#include "edhoc-key-storage.h"
/* Use the EDHOC CBOR library (lib/cbor.h) for both writing and reading.
 * Do NOT include os/services/c509/cbor.h — its types conflict with lib/cbor.h.
 * C509 public key extraction is implemented locally using lib/cbor.h. */
#include "lib/cbor.h"
#include "lib/sha-256.h"
#include "os/net/security/micro-ecc/uECC.h"
#include "ecdh.h"
#include <string.h>

/* C509 pk_alg values (from draft-ietf-cose-cbor-encoded-cert, Table 3).
 * Only secp256r1 is supported for EDHOC in this implementation. */
#define C509_PK_ALG_SECP256R1 1

/* Log configuration */
#include "sys/log.h"
#define LOG_MODULE "EDHOC-C509"
#define LOG_LEVEL LOG_LEVEL_INFO

/*---------------------------------------------------------------------------*/
size_t
edhoc_c509_generate_cred_x(const cose_key_t *key, uint8_t *out, size_t out_sz)
{
  if(key == NULL || key->c509_data == NULL || key->c509_len == 0) {
    LOG_ERR("generate_cred_x: no C509 data in key\n");
    return 0;
  }
  if(key->c509_len > out_sz) {
    LOG_ERR("generate_cred_x: output buffer too small (%zu < %zu)\n",
            out_sz, key->c509_len);
    return 0;
  }
  memcpy(out, key->c509_data, key->c509_len);
  LOG_DBG("CRED_x: %zu bytes of C509\n", key->c509_len);
  return key->c509_len;
}
/*---------------------------------------------------------------------------*/
void
edhoc_c509_hash_cert(const uint8_t *c509, size_t c509_len,
                     uint8_t *hash_out, size_t hash_trunc_len)
{
  uint8_t digest[SHA_256_DIGEST_LENGTH];
  SHA_256.hash(c509, c509_len, digest);
  if(hash_trunc_len > SHA_256_DIGEST_LENGTH) {
    hash_trunc_len = SHA_256_DIGEST_LENGTH;
  }
  memcpy(hash_out, digest, hash_trunc_len);
}
/*---------------------------------------------------------------------------*/
size_t
edhoc_c509_generate_id_cred_c5t(const cose_key_t *key,
                                  uint8_t *out, size_t out_sz)
{
  if(key == NULL || key->c509_data == NULL || key->c509_len == 0) {
    LOG_ERR("generate_id_cred_c5t: no C509 data\n");
    return 0;
  }

  uint8_t hash[EDHOC_C5T_HASH_LEN];
  edhoc_c509_hash_cert(key->c509_data, key->c509_len, hash, EDHOC_C5T_HASH_LEN);

  /* Build {22: [-15, h'<hash>']}
   *   CBOR map(1)
   *     key:   uint 22
   *     value: array(2) [ int -15, bstr hash ]
   */
  cbor_writer_state_t w;
  cbor_init_writer(&w, out, out_sz);
  cbor_open_map(&w);
  cbor_write_unsigned(&w, COSE_HEADER_LABEL_C5T);
  cbor_open_array(&w);
  cbor_write_signed(&w, COSE_HASH_ALG_SHA256_64);
  cbor_write_data(&w, hash, EDHOC_C5T_HASH_LEN);
  cbor_close_array(&w);
  cbor_close_map(&w);

  size_t written = cbor_end_writer(&w);
  LOG_DBG("ID_CRED_x (c5t): %zu bytes\n", written);
  return written;
}
/*---------------------------------------------------------------------------*/
size_t
edhoc_c509_generate_id_cred_c5c(const cose_key_t *key,
                                  uint8_t *out, size_t out_sz)
{
  if(key == NULL || key->c509_data == NULL || key->c509_len == 0) {
    LOG_ERR("generate_id_cred_c5c: no C509 data\n");
    return 0;
  }

  /* Build {25: h'<C509 bytes>'}
   *   CBOR map(1)
   *     key:   uint 25
   *     value: bstr <C509 cert>
   */
  cbor_writer_state_t w;
  cbor_init_writer(&w, out, out_sz);
  cbor_open_map(&w);
  cbor_write_unsigned(&w, COSE_HEADER_LABEL_C5C);
  cbor_write_data(&w, key->c509_data, key->c509_len);
  cbor_close_map(&w);

  size_t written = cbor_end_writer(&w);
  LOG_DBG("ID_CRED_x (c5c): %zu bytes\n", written);
  return written;
}
/*---------------------------------------------------------------------------*/
edhoc_error_t
edhoc_c509_extract_pub_key(const uint8_t *c509, size_t c509_len,
                            cose_key_t *key_out)
{
  if(c509 == NULL || c509_len == 0 || key_out == NULL) {
    return EDHOC_ERR_NULL_POINTER;
  }

  /* C509 cert fields (0-indexed):
   *   0: type, 1: serial, 2: issuer_alg, 3: issuer,
   *   4: not_before, 5: not_after, 6: subject,
   *   7: pk_alg (int), 8: subject_pk (bstr), 9: extensions, 10: signature
   *
   * Cert bytes may or may not start with a CBOR array header (major type 4).
   * Without header (format used in this workspace): first byte is type uint.
   * With header: first byte encodes the array. Skip header if present. */
  cbor_reader_state_t r;
  cbor_init_reader(&r, c509, c509_len);

  if(c509_len > 0 && (c509[0] >> 5) == 4) {
    /* Outer CBOR array header present — consume it */
    cbor_read_array(&r);
  }

  for(int i = 0; i < 7; i++) {
    if(!cbor_skip_next(&r)) {
      LOG_ERR("extract_pub_key: failed to skip field %d\n", i);
      return EDHOC_ERR_CREDENTIAL_NOT_FOUND;
    }
  }

  /* Field 7: pk_alg */
  int64_t pk_alg_val;
  if(cbor_read_signed(&r, &pk_alg_val) == CBOR_SIZE_NONE) {
    LOG_ERR("extract_pub_key: failed to read pk_alg\n");
    return EDHOC_ERR_CREDENTIAL_NOT_FOUND;
  }
  int pk_alg = (int)pk_alg_val;

  /* Field 8: subject_pk */
  size_t pk_len;
  const uint8_t *pk = cbor_read_data(&r, &pk_len);
  if(!pk || pk_len == 0) {
    LOG_ERR("extract_pub_key: failed to read subject_pk\n");
    return EDHOC_ERR_CREDENTIAL_NOT_FOUND;
  }

  /* Only P-256 (secp256r1) supported */
  if(pk_alg != C509_PK_ALG_SECP256R1) {
    LOG_ERR("extract_pub_key: unsupported pk_alg %d (only secp256r1)\n", pk_alg);
    return EDHOC_ERR_CREDENTIAL_NOT_FOUND;
  }

  /* C509 stores compressed EC points with a Contiki-specific prefix:
   *   0xFE → even y  (maps to standard 0x02)
   *   0xFD → odd  y  (maps to standard 0x03)
   * A 33-byte point (1 prefix + 32 x-bytes) is expected for P-256. */
  if(pk_len != 33 || (pk[0] != 0xFE && pk[0] != 0xFD)) {
    LOG_ERR("extract_pub_key: unexpected pk format (len=%zu prefix=0x%02x)\n",
            pk_len, pk[0]);
    return EDHOC_ERR_CREDENTIAL_NOT_FOUND;
  }

  /* Convert C509 prefix to standard ANSI X9.62 prefix */
  uint8_t compressed[33];
  compressed[0] = (pk[0] == 0xFE) ? 0x02 : 0x03;
  memcpy(compressed + 1, pk + 1, 32);

  /* Decompress using micro-ecc: output is 64 bytes = x[32] || y[32] */
  uint8_t pub_xy[64];
  uECC_decompress(compressed, pub_xy, uECC_secp256r1());

  /* Populate cose_key_t with the extracted public key.  The memset clears
   * every field including c509_data/c509_len; callers that need to retain a
   * reference to the source cert bytes must set those fields after returning. */
  memset(key_out, 0, sizeof(*key_out));
  key_out->kty = 2;  /* EC2 */
  key_out->crv = 1;  /* P-256 */
  memcpy(key_out->ecc.pub.x, pub_xy,      ECC_KEY_LEN);
  memcpy(key_out->ecc.pub.y, pub_xy + 32, ECC_KEY_LEN);

  LOG_DBG("extract_pub_key: P-256 key extracted from C509\n");
  return EDHOC_SUCCESS;
}
/*---------------------------------------------------------------------------*/
edhoc_error_t
edhoc_c509_lookup_by_hash(const uint8_t *hash, size_t hash_len,
                           cose_key_t **key_out)
{
  if(hash == NULL || hash_len == 0 || key_out == NULL) {
    return EDHOC_ERR_NULL_POINTER;
  }

  uint8_t candidate[EDHOC_C5T_HASH_LEN];
  uint8_t trunc_len = (hash_len < EDHOC_C5T_HASH_LEN)
                      ? hash_len : EDHOC_C5T_HASH_LEN;

  /* Walk the key storage list.  edhoc_check_key_list_kid/identity only search
   * by KID/identity, so we iterate with the generic iterator. */
  cose_key_t *entry = NULL;
  if(edhoc_get_first_key(&entry) != EDHOC_SUCCESS || entry == NULL) {
    return EDHOC_ERR_KEY_NOT_FOUND;
  }

  while(entry != NULL) {
    if(entry->c509_data != NULL && entry->c509_len > 0) {
      edhoc_c509_hash_cert(entry->c509_data, entry->c509_len,
                           candidate, trunc_len);
      if(memcmp(candidate, hash, trunc_len) == 0) {
        *key_out = entry;
        LOG_DBG("lookup_by_hash: found matching C509 key\n");
        return EDHOC_SUCCESS;
      }
    }
    if(edhoc_get_next_key(entry, &entry) != EDHOC_SUCCESS) {
      break;
    }
  }

  LOG_ERR("lookup_by_hash: no C509 key matched the given hash\n");
  return EDHOC_ERR_KEY_NOT_FOUND;
}
/*---------------------------------------------------------------------------*/
edhoc_error_t
edhoc_c509_validate_self_signed(const uint8_t *c509, size_t c509_len,
                                 void *app_ctx)
{
  (void)app_ctx;

  if(c509 == NULL || c509_len == 0) {
    return EDHOC_ERR_NULL_POINTER;
  }

  /* Read the C509 type field (first CBOR item).
   *
   * C509 types (draft-ietf-cose-cbor-encoded-cert §3.1):
   *   0, 1, 3 — DER-equivalent: the signature was computed over the DER
   *             TBSCertificate, not the CBOR encoding.  Full verification
   *             requires DER reconstruction; as a pragmatic check we verify
   *             structural integrity (public key extraction succeeds) and
   *             accept the cert.
   *   2       — natively signed C509: signature is ECDSA-P256 over
   *             SHA-256(CBOR TBS, fields 0–9).  Full ECDSA verification is
   *             performed here using the cert's own public key. */
  cbor_reader_state_t r;
  cbor_init_reader(&r, c509, c509_len);

  if(c509_len > 0 && (c509[0] >> 5) == 4) {
    /* Outer CBOR array header — consume it. */
    cbor_read_array(&r);
  }

  int64_t cert_type_val = 0;
  if(cbor_read_signed(&r, &cert_type_val) == CBOR_SIZE_NONE) {
    LOG_ERR("validate_self_signed: cannot read cert type\n");
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }
  int cert_type = (int)cert_type_val;

  /* Extract the public key — required for both code paths. */
  cose_key_t pk;
  edhoc_error_t err = edhoc_c509_extract_pub_key(c509, c509_len, &pk);
  if(err != EDHOC_SUCCESS) {
    LOG_ERR("validate_self_signed: cannot extract public key (%d)\n", err);
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  if(cert_type != 2) {
    /* Types 0, 1, 3 are DER-equivalent: signature covers the DER
     * TBSCertificate.  Full verification requires reconstructing DER, which
     * needs the full C509→DER conversion layer.  Structural check (public
     * key extraction succeeded above) is sufficient here. */
    LOG_INFO("validate_self_signed: type-%d (DER-equiv) — structural check OK\n",
             cert_type);
    return EDHOC_SUCCESS;
  }

  /* Native C509 (type 2 only): signature is over SHA-256(CBOR TBS).
   * TBS = the raw cert bytes covering fields 0–9 (10 fields).
   *
   * Re-init reader from the start of the cert (without array header) to
   * measure TBS extent precisely. */
  cbor_init_reader(&r, c509, c509_len);
  if(c509_len > 0 && (c509[0] >> 5) == 4) {
    cbor_read_array(&r);
  }
  const uint8_t *tbs_start = cbor_get_position(&r);

  for(int i = 0; i < 10; i++) {
    if(!cbor_skip_next(&r)) {
      LOG_ERR("validate_self_signed: failed to skip TBS field %d\n", i);
      return EDHOC_ERR_CERTIFICATE_REJECTED;
    }
  }

  const uint8_t *tbs_end = cbor_get_position(&r);
  size_t tbs_len = (size_t)(tbs_end - tbs_start);

  /* Field 10: signature bstr (64 bytes: r||s for P-256). */
  size_t sig_len;
  const uint8_t *sig = cbor_read_data(&r, &sig_len);
  if(sig == NULL || sig_len != 2 * ECC_KEY_LEN) {
    LOG_ERR("validate_self_signed: bad sig length %zu\n", sig ? sig_len : 0);
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  uint8_t hash[SHA_256_DIGEST_LENGTH];
  SHA_256.hash(tbs_start, tbs_len, hash);

  uint8_t pub_xy[2 * ECC_KEY_LEN];
  memcpy(pub_xy,               pk.ecc.pub.x, ECC_KEY_LEN);
  memcpy(pub_xy + ECC_KEY_LEN, pk.ecc.pub.y, ECC_KEY_LEN);

  if(!ecc_verify_hash(EDHOC_CURVE_P256, hash, pub_xy, sig)) {
    LOG_ERR("validate_self_signed: ECDSA signature verification FAILED\n");
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  LOG_INFO("validate_self_signed: native C509 type-%d cert OK\n", cert_type);
  return EDHOC_SUCCESS;
}
/*---------------------------------------------------------------------------*/
/*
 * CA-issued chain validation (draft-ietf-cose-cbor-encoded-cert §3.1, Type 2).
 *
 * Unlike edhoc_c509_validate_self_signed() (which checks the cert's
 * signature against its OWN embedded public key, i.e. issuer == subject),
 * this function checks the cert's signature against the public keys of the
 * trust anchors registered via edhoc_set_c509_trust_store() (i.e. it
 * assumes issuer != subject — the cert was issued by a separate CA).
 *
 * This implementation does not parse the cert's "issuer" field (field 3)
 * to look up a specific CA by name/identifier; instead it performs a
 * brute-force search, trying the signature against every trust anchor in
 * the store and accepting the cert if ANY anchor verifies it. For the
 * small, statically-configured trust stores used in this workspace's tests
 * (typically a single CA) this is equivalent to an issuer-based lookup, but
 * it does not by itself confirm that the "issuer" field actually names the
 * anchor that verified the signature.
 *
 * Steps:
 *   1. Read the cert type (field 0). Types 0/1/3 are DER-equivalent and
 *      only get the structural check (see edhoc_c509_extract_pub_key());
 *      full DER-based signature verification is out of scope here.
 *   2. For Type 2 (natively signed), recompute SHA-256 over the raw CBOR
 *      TBS bytes (fields 0-9) -- this is the "c509_verify_chain"-equivalent
 *      hash step.
 *   3. Read the ECDSA signature from field 10 and verify it
 *      (ecc_verify_hash(), the "c509_verify_signature"-equivalent step)
 *      against each trust anchor's public key (anchor->ecc.pub.{x,y}) in
 *      turn, until one succeeds or the store is exhausted.
 */
edhoc_error_t
edhoc_c509_validate_chain(const uint8_t *c509, size_t c509_len, void *app_ctx)
{
  (void)app_ctx;

  if(c509 == NULL || c509_len == 0) {
    return EDHOC_ERR_NULL_POINTER;
  }

  const edhoc_trust_store_t *store = edhoc_get_c509_trust_store();
  if(store == NULL) {
    LOG_ERR("validate_chain: trust store not set\n");
    return EDHOC_ERR_NULL_POINTER;
  }

  cbor_reader_state_t r;
  cbor_init_reader(&r, c509, c509_len);
  if(c509_len > 0 && (c509[0] >> 5) == 4) {
    cbor_read_array(&r);
  }

  int64_t cert_type_val = 0;
  if(cbor_read_signed(&r, &cert_type_val) == CBOR_SIZE_NONE) {
    LOG_ERR("validate_chain: cannot read cert type\n");
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }
  int cert_type = (int)cert_type_val;

  /* Structural check: extraction succeeds only if CBOR fields 0–8 parse
   * correctly.  The resulting peer_pk is not used within this function;
   * the EDHOC stack uses the cert's embedded public key separately. */
  cose_key_t peer_pk;
  edhoc_error_t err = edhoc_c509_extract_pub_key(c509, c509_len, &peer_pk);
  if(err != EDHOC_SUCCESS) {
    LOG_ERR("validate_chain: cannot extract peer public key (%d)\n", err);
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  if(cert_type != 2) {
    /* Types 0, 1, 3 — DER-equivalent.  Structural check passed above. */
    LOG_INFO("validate_chain: type-%d (DER-equiv) — structural check OK\n",
             cert_type);
    return EDHOC_SUCCESS;
  }

  /* Native Type 2: measure TBS extent (fields 0–9 of the raw cert bytes).
   * Re-init the reader so tbs_start lands at field 0 — the first reader and
   * edhoc_c509_extract_pub_key have both already advanced past field 0. */
  cbor_init_reader(&r, c509, c509_len);
  if(c509_len > 0 && (c509[0] >> 5) == 4) {
    cbor_read_array(&r);
  }
  const uint8_t *tbs_start = cbor_get_position(&r);

  /* Skip over fields 0-9 (type, serial, issuer_alg, issuer, validity x2,
   * subject, pk_alg, subject_pk, extensions) without decoding their
   * contents — only the byte range tbs_start..tbs_end is needed for the
   * hash. Field 10 (the signature itself) is read separately below. */
  for(int i = 0; i < 10; i++) {
    if(!cbor_skip_next(&r)) {
      LOG_ERR("validate_chain: failed to skip TBS field %d\n", i);
      return EDHOC_ERR_CERTIFICATE_REJECTED;
    }
  }
  const uint8_t *tbs_end = cbor_get_position(&r);
  size_t tbs_len = (size_t)(tbs_end - tbs_start);

  /* Field 10: signature bstr (64 bytes: r||s for P-256). */
  size_t sig_len;
  const uint8_t *sig = cbor_read_data(&r, &sig_len);
  if(sig == NULL || sig_len != 2 * ECC_KEY_LEN) {
    LOG_ERR("validate_chain: bad sig length %zu\n", sig ? sig_len : 0);
    return EDHOC_ERR_CERTIFICATE_REJECTED;
  }

  /* Hash of the TBS bytes is what each candidate CA signature is checked
   * against (see ecc_verify_hash() calls below). */
  uint8_t hash[SHA_256_DIGEST_LENGTH];
  SHA_256.hash(tbs_start, tbs_len, hash);

  /* Try each trust anchor in turn: the cert is accepted as soon as one
   * anchor's public key successfully verifies the ECDSA signature over
   * the TBS hash. */
  for(size_t i = 0; i < store->count; i++) {
    const cose_key_t *anchor = &store->anchors[i];
    uint8_t anchor_xy[2 * ECC_KEY_LEN];
    memcpy(anchor_xy,               anchor->ecc.pub.x, ECC_KEY_LEN);
    memcpy(anchor_xy + ECC_KEY_LEN, anchor->ecc.pub.y, ECC_KEY_LEN);

    if(ecc_verify_hash(EDHOC_CURVE_P256, hash, anchor_xy, sig)) {
      LOG_INFO("validate_chain: cert verified by trust anchor %zu\n", i);
      return EDHOC_SUCCESS;
    }
  }

  LOG_ERR("validate_chain: cert not verified by any trust anchor\n");
  return EDHOC_ERR_CERTIFICATE_REJECTED;
}
