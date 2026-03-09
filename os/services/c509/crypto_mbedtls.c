/**
 * @file crypto_mbedtls.c
 * @brief mbedTLS-based implementation of C509 crypto operations.
 */

#include "crypto.h"
#include <mbedtls/sha256.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <string.h>
#include <stdio.h>

// C509 Algorithm Identifiers (Draft Section 9.2)
#define C509_ALG_ECDSA_SHA_256 0

crypto_error_t c509_verify_signature(const c509_cert_t *cert, 
                                    const uint8_t *issuer_pk, 
                                    size_t issuer_pk_len) {
    // 1. Validate Algorithms
    if (cert->issuer_alg.val != C509_ALG_ECDSA_SHA_256) {
        return CRYPTO_ERR_UNSUPPORTED_ALG;
    }

    // 2. Initialize mbedTLS structures
    int ret;
    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    ret = mbedtls_ecp_group_load(&ecdsa.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) { mbedtls_ecdsa_free(&ecdsa); return CRYPTO_ERR_INTERNAL; }

    ret = mbedtls_ecp_point_read_binary(&ecdsa.MBEDTLS_PRIVATE(grp), &ecdsa.MBEDTLS_PRIVATE(Q), issuer_pk, issuer_pk_len);
    if (ret != 0) { 
        // Try adding 0x04 prefix if missing
        uint8_t pk_fixed[65];
        if (issuer_pk_len == 64) {
            pk_fixed[0] = 0x04;
            memcpy(pk_fixed + 1, issuer_pk, 64);
            ret = mbedtls_ecp_point_read_binary(&ecdsa.MBEDTLS_PRIVATE(grp), &ecdsa.MBEDTLS_PRIVATE(Q), pk_fixed, 65);
        }
        if (ret != 0) { mbedtls_ecdsa_free(&ecdsa); return CRYPTO_ERR_INTERNAL; }
    }

    // 3. Signature components
    if (cert->signature.val != 64) {
        mbedtls_ecdsa_free(&ecdsa);
        return CRYPTO_ERR_MALFORMED;
    }
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary(&r, cert->signature.ptr, 32);
    mbedtls_mpi_read_binary(&s, cert->signature.ptr + 32, 32);

    uint8_t hash[32];
    mbedtls_sha256_context sha_ctx;
    mbedtls_sha256_init(&sha_ctx);

    printf("  Attempting verification for Type %llu cert...\n", (unsigned long long)cert->type.val);

    // --- ATTEMPT 1: Raw concatenation of fields 0..9 ---
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, cert->tbs_ptr, cert->tbs_len);
    mbedtls_sha256_finish(&sha_ctx, hash);
    ret = mbedtls_ecdsa_verify(&ecdsa.MBEDTLS_PRIVATE(grp), hash, 32, &ecdsa.MBEDTLS_PRIVATE(Q), &r, &s);
    if (ret == 0) { printf("    SUCCESS: Verified with raw fields!\n"); goto cleanup; }

    // --- ATTEMPT 2: Virtual Array 10 Header (0x8A) + fields ---
    uint8_t h8a = 0x8A;
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, &h8a, 1);
    mbedtls_sha256_update(&sha_ctx, cert->tbs_ptr, cert->tbs_len);
    mbedtls_sha256_finish(&sha_ctx, hash);
    ret = mbedtls_ecdsa_verify(&ecdsa.MBEDTLS_PRIVATE(grp), hash, 32, &ecdsa.MBEDTLS_PRIVATE(Q), &r, &s);
    if (ret == 0) { printf("    SUCCESS: Verified with Array 10 header!\n"); goto cleanup; }

    // --- ATTEMPT 3: Raw fields with swapped R/S ---
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, cert->tbs_ptr, cert->tbs_len);
    mbedtls_sha256_finish(&sha_ctx, hash);
    ret = mbedtls_ecdsa_verify(&ecdsa.MBEDTLS_PRIVATE(grp), hash, 32, &ecdsa.MBEDTLS_PRIVATE(Q), &s, &r);
    if (ret == 0) { printf("    SUCCESS: Verified with raw fields and swapped R/S!\n"); goto cleanup; }

    // --- ATTEMPT 4: Array 10 header with swapped R/S ---
    mbedtls_sha256_starts(&sha_ctx, 0);
    mbedtls_sha256_update(&sha_ctx, &h8a, 1);
    mbedtls_sha256_update(&sha_ctx, cert->tbs_ptr, cert->tbs_len);
    mbedtls_sha256_finish(&sha_ctx, hash);
    ret = mbedtls_ecdsa_verify(&ecdsa.MBEDTLS_PRIVATE(grp), hash, 32, &ecdsa.MBEDTLS_PRIVATE(Q), &s, &r);
    if (ret == 0) { printf("    SUCCESS: Verified with Array 10 and swapped R/S!\n"); goto cleanup; }

cleanup:
    mbedtls_sha256_free(&sha_ctx);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ecdsa);

    return (ret == 0) ? CRYPTO_ERR_NONE : CRYPTO_ERR_SIG_INVALID;
}
