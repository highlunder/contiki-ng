/**
 * @file crypto_mbedtls.c
 * @brief mbedTLS-based implementation of C509 crypto operations.
 */

#include "crypto.h"
#include "c509_registry.h"
#include <mbedtls/sha256.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <string.h>

crypto_error_t c509_verify_signature(const c509_cert_t *cert,
                                     const uint8_t *issuer_pk,
                                     size_t issuer_pk_len) {
    if (cert->issuer_alg.val != C509_SIG_ECDSA_SHA256) {
        return CRYPTO_ERR_UNSUPPORTED_ALG;
    }

    int ret;
    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    ret = mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
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
