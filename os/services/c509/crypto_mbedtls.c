/**
 * @file crypto_mbedtls.c
 * @brief mbedTLS-based implementation of C509 crypto operations.
 */

#include "crypto.h"
#include "c509_registry.h"
#include "ed25519_verify.h"
#include <mbedtls/sha256.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <string.h>

/**
 * @brief Verify a C509 certificate's signature against its issuer's public key.
 *
 * Dispatches on `cert->issuer_alg` (the C509 issuerSignatureAlgorithm field):
 *  - C509_SIG_ED25519: raw RFC 8032 PureEdDSA verification via
 *    ed25519_verify(), using the 64-byte signature directly and a 32-byte
 *    compressed public key (no hashing performed here — Ed25519 hashes the
 *    message internally).
 *  - C509_SIG_ECDSA_SHA256: SHA-256 over the TBS bytes followed by
 *    mbedtls_ecdsa_verify() on the curve identified by issuer_pk_alg (see
 *    below), with the 64-byte signature split into r||s (each 32 bytes).
 *  - All other algorithms: CRYPTO_ERR_UNSUPPORTED_ALG.
 *
 * In both supported cases, the data that was signed is
 * `cert->tbs_ptr[0 .. cert->tbs_len)` — the raw CBOR TBS (To-Be-Signed)
 * sequence as it appears in the original C509 buffer (see c509_cert_t in
 * c509.h), not the reconstructed DER TBSCertificate.
 *
 * @param cert          Parsed C509 certificate whose signature is checked.
 * @param issuer_pk     Issuer's public key bytes (32-byte compressed Ed25519
 *                      point, or 64/65-byte EC point for ECDSA).
 * @param issuer_pk_len Length of issuer_pk in bytes.
 * @param issuer_pk_alg Issuer's C509 public key algorithm ID. For ECDSA,
 *                      selects the EC group (secp256r1, brainpoolP256r1,
 *                      ...); 0 or unrecognized defaults to secp256r1.
 * @return CRYPTO_ERR_NONE if the signature is valid, CRYPTO_ERR_SIG_INVALID
 *         if it is well-formed but does not verify, CRYPTO_ERR_MALFORMED if
 *         the signature/key lengths are inconsistent with the algorithm,
 *         CRYPTO_ERR_UNSUPPORTED_ALG for unsupported issuer_alg values, or
 *         CRYPTO_ERR_INTERNAL on an mbedTLS internal failure.
 */
crypto_error_t c509_verify_signature(const c509_cert_t *cert,
                                     const uint8_t *issuer_pk,
                                     size_t issuer_pk_len,
                                     int64_t issuer_pk_alg) {
    if (cert->issuer_alg.val == C509_SIG_ED25519) {
        if (cert->signature.val != 64 || issuer_pk_len != 32)
            return CRYPTO_ERR_MALFORMED;
        return (ed25519_verify(issuer_pk, cert->signature.ptr,
                               cert->tbs_ptr, cert->tbs_len) == 0)
               ? CRYPTO_ERR_NONE : CRYPTO_ERR_SIG_INVALID;
    }

    if (cert->issuer_alg.val != C509_SIG_ECDSA_SHA256) {
        return CRYPTO_ERR_UNSUPPORTED_ALG;
    }

    mbedtls_ecp_group_id gid;
    switch (issuer_pk_alg) {
        case C509_PK_SECP384R1:       gid = MBEDTLS_ECP_DP_SECP384R1; break;
        case C509_PK_SECP521R1:       gid = MBEDTLS_ECP_DP_SECP521R1; break;
        case C509_PK_BRAINPOOLP256R1: gid = MBEDTLS_ECP_DP_BP256R1;   break;
        case C509_PK_BRAINPOOLP384R1: gid = MBEDTLS_ECP_DP_BP384R1;   break;
        case C509_PK_BRAINPOOLP512R1: gid = MBEDTLS_ECP_DP_BP512R1;   break;
        case C509_PK_SECP256R1:
        default:                      gid = MBEDTLS_ECP_DP_SECP256R1; break;
    }

    int ret;
    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    ret = mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), gid);
    if (ret != 0) { mbedtls_ecdsa_free(&ecdsa); return CRYPTO_ERR_INTERNAL; }

    ret = mbedtls_ecp_point_read_binary(&ecdsa.MBEDTLS_PRIVATE(grp),
                                        &ecdsa.MBEDTLS_PRIVATE(Q),
                                        issuer_pk, issuer_pk_len);
    if (ret != 0) {
        /* Accept raw 64-byte uncompressed point without the 0x04 prefix. */
        uint8_t pk_fixed[65];
        if (issuer_pk_len == 64) {
            pk_fixed[0] = 0x04;
            memcpy(pk_fixed + 1, issuer_pk, 64);
            ret = mbedtls_ecp_point_read_binary(&ecdsa.MBEDTLS_PRIVATE(grp),
                                                &ecdsa.MBEDTLS_PRIVATE(Q),
                                                pk_fixed, 65);
        } else if (issuer_pk_len == 33 &&
                   (issuer_pk[0] == 0xFE || issuer_pk[0] == 0xFD)) {
            /* C509-compressed point (0xFE/0xFD prefix instead of SEC1's
             * 0x02/0x03), e.g. an intermediate CA's subject_pk propagated
             * directly from the parsed certificate by c509_verify_chain(). */
            uint8_t pk_fixed33[33];
            memcpy(pk_fixed33, issuer_pk, 33);
            pk_fixed33[0] = (issuer_pk[0] == 0xFE) ? 0x02 : 0x03;
            ret = mbedtls_ecp_point_read_binary(&ecdsa.MBEDTLS_PRIVATE(grp),
                                                &ecdsa.MBEDTLS_PRIVATE(Q),
                                                pk_fixed33, 33);
        }
        if (ret != 0) { mbedtls_ecdsa_free(&ecdsa); return CRYPTO_ERR_INTERNAL; }
    }

    if (cert->signature.val != 64) {
        mbedtls_ecdsa_free(&ecdsa);
        return CRYPTO_ERR_MALFORMED;
    }

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary(&r, cert->signature.ptr, 32);
    mbedtls_mpi_read_binary(&s, cert->signature.ptr + 32, 32);

    /* TBS is a CBOR Sequence — the raw concatenation of fields 0–9 with no
     * array wrapper.  See draft-ietf-cose-cbor-encoded-cert-19 Section 4. */
    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, cert->tbs_ptr, cert->tbs_len);
    mbedtls_sha256_finish(&sha_ctx, hash);
    mbedtls_sha256_free(&sha_ctx);

    ret = mbedtls_ecdsa_verify(&ecdsa.MBEDTLS_PRIVATE(grp), hash, 32,
                               &ecdsa.MBEDTLS_PRIVATE(Q), &r, &s);

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ecdsa);

    return (ret == 0) ? CRYPTO_ERR_NONE : CRYPTO_ERR_SIG_INVALID;
}
