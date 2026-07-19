/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   TrustZone secure-world attestation Root of Trust (see tz-attest.h). Wraps the
 *   portable RoT core (os/services/attestation/ra-rot) in secure-gateway veneers,
 *   validating every normal-world pointer with cmse_check_address_range() and
 *   copying NS inputs into secure buffers before use -- the same pattern as the
 *   in-tree tz-radio secure service.
 *
 *   Signing uses Monocypher Ed25519 for the P2 bring-up (matches the test backend);
 *   a CC312/uECC backend and sealed key generation are the follow-up. The
 *   attestation private key never crosses the veneer.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "tz-attest.h"
#include "trustzone/tz-api.h"
#include "region_defs.h"

#include "ra-rot.h"
#include "ra-cose.h"
#include "monocypher-ed25519.h"

#include <arm_cmse.h>
#include <string.h>

#include "sys/log.h"
#define LOG_MODULE "TZAttest"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Secure-resident attestation keypair. P2 bring-up: derived from a FIXED seed.
 * Replace with sealed on-device key generation (secure RNG + KMU). */
static uint8_t attest_sk[64];
static uint8_t attest_pk[32];
static int keys_ready;

/* Secure staging buffers -- NS inputs are copied here before use. */
static uint8_t sec_nonce[64];
static uint8_t sec_ueid[64];
static uint8_t sec_binder[RA_BINDER_HASH_LEN];
static uint8_t sec_evidence[512];

/*---------------------------------------------------------------------------*/
static void
ensure_keys(void)
{
  if(!keys_ready) {
    uint8_t seed[32];
    for(int i = 0; i < 32; i++) {
      seed[i] = (uint8_t)(0x40 + i);
    }
    crypto_ed25519_key_pair(attest_sk, attest_pk, seed);
    keys_ready = 1;
  }
}
/*---------------------------------------------------------------------------*/
/* The RoT signing primitive (secure world; the key never leaves). */
static void
rot_sign(void *ctx, const uint8_t *tbs, size_t tbslen, uint8_t sig[64])
{
  (void)ctx;
  crypto_ed25519_sign(sig, attest_sk, tbs, tbslen);
}
/*---------------------------------------------------------------------------*/
CC_TRUSTZONE_SECURE_CALL int
tz_attest_public_key(uint8_t out[32])
{
  if(cmse_check_address_range(out, 32, CMSE_NONSECURE) == NULL) {
    return -1;
  }
  ensure_keys();
  memcpy(out, attest_pk, 32);
  return 0;
}
/*---------------------------------------------------------------------------*/
CC_TRUSTZONE_SECURE_CALL int
tz_attest_build_evidence(const uint8_t *nonce, size_t noncelen,
                         const uint8_t *ueid, size_t ueidlen,
                         const uint8_t *binder, size_t binderlen,
                         uint8_t *out, size_t out_sz, size_t *out_len)
{
  ra_rot_target_t target;
  size_t local_len;

  /* Bound-check against the secure staging buffers. */
  if(noncelen > sizeof(sec_nonce) || ueidlen > sizeof(sec_ueid) ||
     binderlen > sizeof(sec_binder)) {
    return -1;
  }
  /* Validate EVERY normal-world pointer lies in NS memory (anti-confused-deputy). */
  if(cmse_check_address_range((void *)nonce, noncelen, CMSE_NONSECURE) == NULL ||
     cmse_check_address_range((void *)ueid, ueidlen, CMSE_NONSECURE) == NULL ||
     cmse_check_address_range((void *)binder, binderlen, CMSE_NONSECURE) == NULL ||
     cmse_check_address_range(out_len, sizeof(*out_len), CMSE_NONSECURE) == NULL ||
     cmse_check_address_range(out, out_sz, CMSE_NONSECURE) == NULL) {
    LOG_ERR("build_evidence: invalid NS pointer\n");
    return -1;
  }
  memcpy(sec_nonce, nonce, noncelen);
  memcpy(sec_ueid, ueid, ueidlen);
  memcpy(sec_binder, binder, binderlen);
  ensure_keys();

  /* The measurement target is the normal-world application image region. The RoT
   * measures it (the NS caller cannot influence the measurement). */
  target.image = (const uint8_t *)NS_ROM_ALIAS(NS_IMAGE_PRIMARY_PARTITION_OFFSET);
  target.image_len = (size_t)IMAGE_NS_CODE_SIZE;

  if(ra_rot_build_evidence(&target, ra_cose_protected_eddsa, 3,
                           sec_nonce, noncelen, sec_ueid, ueidlen,
                           sec_binder, binderlen,
                           sec_evidence, sizeof(sec_evidence), &local_len,
                           rot_sign, NULL) != 0) {
    return -1;
  }
  if(local_len > out_sz) {
    return -1;
  }
  memcpy(out, sec_evidence, local_len);
  *out_len = local_len;
  return 0;
}
