/*
 * Standalone test for uECC_vli_mult on nRF52840.
 *
 * Tests that the 256-bit × 256-bit field multiplication (used by EDHOC's
 * ephemeral key generation and ECDH) produces correct results.  Runs two
 * cases with known answers computed off-line (Python/gmpy2).
 *
 * SECURITY NOTICE: Test credentials only. Not for production use.
 */

#include "contiki.h"
#include "sys/log.h"
#include "uECC.h"
#include "uECC_vli.h"
#include "lib/sha-256.h"

#define LOG_MODULE "uecc-mult-test"
#define LOG_LEVEL  LOG_LEVEL_DBG

/* 256-bit operands stored as 8 × uint32_t little-endian (uECC convention) */

/* Case 1: A = 1, B = 1  →  A*B = 1 (512-bit) */
static const uint32_t case1_a[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
static const uint32_t case1_b[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
static const uint32_t case1_expected[16] = {
    1, 0, 0, 0, 0, 0, 0, 0,   /* low 256 bits */
    0, 0, 0, 0, 0, 0, 0, 0    /* high 256 bits */
};

/*
 * Case 2: A = 0xFFFFFFFF (in lowest word), B = 0xFFFFFFFF (in lowest word)
 *   A*B = 0xFFFFFFFE_00000001 (64-bit, zero-padded to 512 bits)
 */
static const uint32_t case2_a[8] = { 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0 };
static const uint32_t case2_b[8] = { 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0 };
static const uint32_t case2_expected[16] = {
    0x00000001, 0xFFFFFFFE, 0, 0, 0, 0, 0, 0,
    0,          0,          0, 0, 0, 0, 0, 0
};

/*
 * Case 3: two 256-bit values with all words non-zero.
 *   A = [0x00000001, 0x00000002, 0x00000003, 0x00000004,
 *        0x00000005, 0x00000006, 0x00000007, 0x00000008]
 *   B = [0x00000008, 0x00000007, 0x00000006, 0x00000005,
 *        0x00000004, 0x00000003, 0x00000002, 0x00000001]
 *   Result computed by Python:
 *     a = 1 + 2*2^32 + 3*2^64 + ... + 8*2^224
 *     b = 8 + 7*2^32 + 6*2^64 + ... + 1*2^224
 *     p = a * b
 *   Python result (little-endian 32-bit words):
 *   [0x00000008, 0x00000018, 0x00000038, 0x00000068,
 *    0x000000A8, 0x000000F8, 0x00000158, 0x001C01C8,
 *    0x001A0140, 0x001601B8, 0x00100130, 0x000800A8,
 *    0x00000020, 0x00000038, 0x00000028, 0x00000008]
 */
static const uint32_t case3_a[8] = {
    0x00000001, 0x00000002, 0x00000003, 0x00000004,
    0x00000005, 0x00000006, 0x00000007, 0x00000008
};
static const uint32_t case3_b[8] = {
    0x00000008, 0x00000007, 0x00000006, 0x00000005,
    0x00000004, 0x00000003, 0x00000002, 0x00000001
};
/* Computed with Python3: a*b = [1+2x+3x^2+...+8x^7] * [8+7x+...+1x^7], x=2^32
 * All partial sums fit in 32 bits so no carry propagation between words. */
static const uint32_t case3_expected[16] = {
    0x00000008, 0x00000017, 0x0000002C, 0x00000046,
    0x00000064, 0x00000085, 0x000000A8, 0x000000CC,
    0x000000A8, 0x00000085, 0x00000064, 0x00000046,
    0x0000002C, 0x00000017, 0x00000008, 0x00000000
};

/*
 * Case 4: random 256-bit values (seed=42, via Python random module).
 * Exercises full carry propagation across all 16 product words.
 */
static const uint32_t case4_a[8] = {
    0xa3b1799d, 0x46685257, 0x392456de, 0xbc8960a9,
    0x6c031199, 0x07a0ca6e, 0x37f8a88b, 0x8b8148f6
};
static const uint32_t case4_b[8] = {
    0x386ecbe0, 0x96da1dac, 0xce4a2bbd, 0xb2b9437a,
    0x571aa876, 0x27cd8130, 0x562b0f79, 0x17be3111
};
static const uint32_t case4_expected[16] = {
    0x902fe860, 0x85c132d5, 0x826421e2, 0x83a09594,
    0x07152a57, 0x3cdbea42, 0x54e4285b, 0x29f2ef37,
    0xfd1907f2, 0x5837f037, 0x00ef8a7c, 0x503fb516,
    0xe9920aef, 0x75e0714d, 0x7746c06a, 0x0cf0423f
};

/*
 * SHA-256 Sigma test: check the capital-Sigma (round-function) ROTR amounts.
 *
 * Sigma0 uses ROTR(2, 13, 22); Sigma1 uses ROTR(6, 11, 25).
 * These are different from the MSCH sigma amounts (7, 17, 18, 19) that passed.
 * Uses SHA-256 initial hash constants as test vectors (easily verified externally).
 *
 * S0(0x6A09E667) = ROTR(2) ^ ROTR(13) ^ ROTR(22):
 *   ROTR(0x6A09E667,  2) = 0xDA827999
 *   ROTR(0x6A09E667, 13) = 0x333B504F
 *   ROTR(0x6A09E667, 22) = 0x27999DA8
 *   S0(0x6A09E667) = 0xDA827999 ^ 0x333B504F ^ 0x27999DA8 = 0xCE20B47E
 *
 * S1(0x510E527F) = ROTR(6) ^ ROTR(11) ^ ROTR(25):
 *   ROTR(0x510E527F,  6) = 0xFD443949
 *   ROTR(0x510E527F, 11) = 0x4FEA21CA
 *   ROTR(0x510E527F, 25) = 0x87293FA8
 *   S1(0x510E527F) = 0xFD443949 ^ 0x4FEA21CA ^ 0x87293FA8 = 0x3587272B
 */
static int
run_sha256_sigma_test(void)
{
#define SIGMA_ROTR(x, n) (((uint32_t)(x) >> (n)) | ((uint32_t)(x) << (32 - (n))))
#define CAP_S0(x) (SIGMA_ROTR(x, 2)  ^ SIGMA_ROTR(x, 13) ^ SIGMA_ROTR(x, 22))
#define CAP_S1(x) (SIGMA_ROTR(x, 6)  ^ SIGMA_ROTR(x, 11) ^ SIGMA_ROTR(x, 25))

    uint32_t a = 0x6A09E667u; /* SHA-256 H[0] initial constant */
    uint32_t e = 0x510E527Fu; /* SHA-256 H[4] initial constant */

    uint32_t r2   = SIGMA_ROTR(a, 2);
    uint32_t r13  = SIGMA_ROTR(a, 13);
    uint32_t r22  = SIGMA_ROTR(a, 22);
    uint32_t s0   = CAP_S0(a);

    uint32_t r6   = SIGMA_ROTR(e, 6);
    uint32_t r11  = SIGMA_ROTR(e, 11);
    uint32_t r25  = SIGMA_ROTR(e, 25);
    uint32_t s1   = CAP_S1(e);

    LOG_DBG("Sigma test a=0x6a09e667:\n");
    LOG_DBG("  ror2 =0x%08lx exp 0xda827999\n", (unsigned long)r2);
    LOG_DBG("  ror13=0x%08lx exp 0x333b504f\n", (unsigned long)r13);
    LOG_DBG("  ror22=0x%08lx exp 0x27999da8\n", (unsigned long)r22);
    LOG_DBG("  S0   =0x%08lx exp 0xce20b47e\n", (unsigned long)s0);
    LOG_DBG("Sigma test e=0x510e527f:\n");
    LOG_DBG("  ror6 =0x%08lx exp 0xfd443949\n", (unsigned long)r6);
    LOG_DBG("  ror11=0x%08lx exp 0x4fea21ca\n", (unsigned long)r11);
    LOG_DBG("  ror25=0x%08lx exp 0x87293fa8\n", (unsigned long)r25);
    LOG_DBG("  S1   =0x%08lx exp 0x3587272b\n", (unsigned long)s1);

    int ok = (r2  == 0xda827999u) && (r13 == 0x333b504fu) &&
             (r22 == 0x27999da8u) && (s0  == 0xce20b47eu) &&
             (r6  == 0xfd443949u) && (r11 == 0x4fea21cau) &&
             (r25 == 0x87293fa8u) && (s1  == 0x3587272bu);
    if(ok) {
        LOG_INFO("SHA-256 Sigma ROTR test PASS\n");
    } else {
        LOG_ERR("SHA-256 Sigma ROTR test FAIL (see DBG above)\n");
    }
    return ok;

#undef CAP_S1
#undef CAP_S0
#undef SIGMA_ROTR
}

/*
 * SHA-256 MSCH diagnostic.
 *
 * Recomputes the message schedule for the "abc" input block entirely in C
 * (compiled to ARM Thumb-2, so the same ROR/LSR instructions fire as in the
 * real sha-256 transform).  Prints sub-steps of W[59] to isolate which
 * operand is wrong in the emulator.
 *
 * Expected key values (verified by manual 32-bit addition):
 *   W[43]=0x27333ba3  W[44]=0x0c4763f2
 *   W[52]=0x84badedd  W[57]=0xebe6b238
 *   W[59]=0x78bc8d4b  (= s1(W[57])+W[52]+s0(W[44])+W[43], all mod 2^32)
 */
static int
run_sha256_msch_diagnostic(void)
{
#define MSCH_ROTR(x, n) (((uint32_t)(x) >> (n)) | ((uint32_t)(x) << (32 - (n))))
#define MSCH_S0(x) (MSCH_ROTR(x, 7)  ^ MSCH_ROTR(x, 18) ^ ((uint32_t)(x) >> 3))
#define MSCH_S1(x) (MSCH_ROTR(x, 17) ^ MSCH_ROTR(x, 19) ^ ((uint32_t)(x) >> 10))

    uint32_t W[64];
    W[0]  = 0x61626380u; /* "abc" + 0x80 padding */
    int i;
    for(i = 1; i < 15; i++) W[i] = 0;
    W[15] = 0x00000018u; /* bit length = 24 */

    for(i = 16; i < 64; i++) {
        W[i] = MSCH_S1(W[i - 2]) + W[i - 7] + MSCH_S0(W[i - 15]) + W[i - 16];
    }

    /* Print key intermediate W values (expected from Python MSCH) */
    LOG_DBG("MSCH W[16]=0x%08lx exp 0x61626380\n", (unsigned long)W[16]);
    LOG_DBG("MSCH W[17]=0x%08lx exp 0x000f0000\n", (unsigned long)W[17]);
    LOG_DBG("MSCH W[43]=0x%08lx exp 0x27333ba3\n", (unsigned long)W[43]);
    LOG_DBG("MSCH W[44]=0x%08lx exp 0x0c4763f2\n", (unsigned long)W[44]);
    LOG_DBG("MSCH W[52]=0x%08lx exp 0x84badedd\n", (unsigned long)W[52]);
    LOG_DBG("MSCH W[57]=0x%08lx exp 0xebe6b238\n", (unsigned long)W[57]);

    /* Break down s1(W[57]) */
    uint32_t w57   = W[57];
    uint32_t r17   = MSCH_ROTR(w57, 17);
    uint32_t r19   = MSCH_ROTR(w57, 19);
    uint32_t lsr10 = w57 >> 10;
    uint32_t s1    = r17 ^ r19 ^ lsr10;
    LOG_DBG("s1(W[57]): ror17=0x%08lx ror19=0x%08lx lsr10=0x%08lx\n",
            (unsigned long)r17, (unsigned long)r19, (unsigned long)lsr10);
    LOG_DBG("s1(W[57])=0x%08lx exp 0x8f619123\n", (unsigned long)s1);

    /* Break down s0(W[44]) */
    uint32_t w44  = W[44];
    uint32_t rr7  = MSCH_ROTR(w44, 7);
    uint32_t rr18 = MSCH_ROTR(w44, 18);
    uint32_t lsr3 = w44 >> 3;
    uint32_t s0   = rr7 ^ rr18 ^ lsr3;
    LOG_DBG("s0(W[44]): ror7=0x%08lx ror18=0x%08lx lsr3=0x%08lx\n",
            (unsigned long)rr7, (unsigned long)rr18, (unsigned long)lsr3);
    LOG_DBG("s0(W[44])=0x%08lx exp 0x3d6ce1a8\n", (unsigned long)s0);

    LOG_DBG("W[59] addends: s1=0x%08lx W52=0x%08lx s0=0x%08lx W43=0x%08lx\n",
            (unsigned long)s1, (unsigned long)W[52],
            (unsigned long)s0, (unsigned long)W[43]);
    LOG_DBG("MSCH W[59]=0x%08lx exp 0x78bc8d4b\n", (unsigned long)W[59]);

    int ok = (W[59] == 0x78bc8d4bu);
    if(ok) {
        LOG_INFO("MSCH W[59] PASS\n");
    } else {
        LOG_ERR("MSCH W[59] FAIL: got 0x%08lx exp 0x78bc8d4b\n",
                (unsigned long)W[59]);
    }
    return ok;

#undef MSCH_S1
#undef MSCH_S0
#undef MSCH_ROTR
}

/*
 * SHA-256 test: known input → known digest.
 * Input: "abc" (3 bytes)
 * Expected SHA-256: ba7816bf8f01cfea414140de5dae2223b00361a396177a9c
 *                   b410ff61f20015ad
 */
static int
run_sha256_test(void)
{
    int abc_ok = 0, empty_ok = 0;
    /* Test 1: SHA-256("abc") */
    {
        static const uint8_t input[] = { 0x61, 0x62, 0x63 };
        static const uint8_t expected[32] = {
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
            0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
            0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        };
        uint8_t digest[32];
        sha_256_hash(input, sizeof(input), digest);
        /* Log full digest to see rotation pattern */
        LOG_DBG("SHA-256('abc') got:\n");
        for(int i = 0; i < 32; i += 4) {
            LOG_DBG("  [%2d] %02x%02x%02x%02x  exp: %02x%02x%02x%02x\n",
                    i, digest[i],digest[i+1],digest[i+2],digest[i+3],
                    expected[i],expected[i+1],expected[i+2],expected[i+3]);
        }
        abc_ok = 1;
        for(int i = 0; i < 32; i++) {
            if(digest[i] != expected[i]) {
                LOG_ERR("SHA-256('abc') FAIL at byte[%d]: got 0x%02x expected 0x%02x\n",
                        i, digest[i], expected[i]);
                abc_ok = 0; break;
            }
        }
        if(abc_ok) { LOG_INFO("SHA-256 'abc' PASS\n"); }
    }

    /* Test 2: SHA-256 of empty string */
    {
        static const uint8_t expected_empty[32] = {
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
            0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
            0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
            0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
        };
        uint8_t digest2[32];
        sha_256_hash(NULL, 0, digest2);
        LOG_DBG("SHA-256('') got: %02x%02x%02x%02x\n",
                digest2[0],digest2[1],digest2[2],digest2[3]);
        empty_ok = 1;
        for(int i = 0; i < 32; i++) {
            if(digest2[i] != expected_empty[i]) {
                LOG_ERR("SHA-256('') FAIL at byte[%d]: got 0x%02x expected 0x%02x\n",
                        i, digest2[i], expected_empty[i]);
                empty_ok = 0; break;
            }
        }
        if(empty_ok) { LOG_INFO("SHA-256 '' PASS\n"); }
        return abc_ok & empty_ok;
    }
}

/*
 * ECDH self-consistency test: generate a key pair, then compute the shared
 * secret of the public key with the private key — the result should equal
 * the public key's x-coordinate multiplied by itself via the curve.
 * Instead, do a simpler check: generate key, verify the point is on the curve.
 *
 * Also test uECC_vli_mult via an indirect path: compute a field squaring
 * (multiply a value by itself) and check the result.
 */
/*
 * RFC 9528 Appendix B.1.2 ECDH test vectors (Method 0, Cipher Suite 2, P-256).
 * Tests that uECC_shared_secret with known (priv, G_Y) gives the known G_XY.
 *
 * All values in uECC little-endian byte order (reversed from RFC big-endian).
 * NOTE: uECC_decompress and uECC_shared_secret external API uses big-endian bytes.
 * These LE vectors must be byte-reversed before passing to uECC API functions.
 */
static const uint8_t rfc9528_x_priv[32] = {
    0x25, 0x95, 0x0f, 0x53, 0xe3, 0x2c, 0xa4, 0x3c, 0x5f, 0x23, 0xef, 0xa8, 0xea, 0xdc, 0x99, 0x02,
    0xdc, 0x1b, 0xb2, 0x45, 0x8d, 0x5a, 0x7d, 0xa3, 0x9b, 0x65, 0xeb, 0x9a, 0xf6, 0xc1, 0x8e, 0x36
};
static const uint8_t rfc9528_gy_x[32] = {
    0xd5, 0xf5, 0x4f, 0x3a, 0xa1, 0x55, 0xf9, 0xa0, 0x8e, 0x2c, 0x42, 0x93, 0xc8, 0x63, 0x37, 0xf3,
    0x49, 0x25, 0x75, 0xdd, 0x36, 0x7a, 0x58, 0xdc, 0xc2, 0x26, 0x0a, 0xf0, 0xd7, 0x01, 0x97, 0x41
};
static const uint8_t rfc9528_gxy_x[32] = {
    0xba, 0x24, 0xa8, 0xf7, 0xec, 0xe5, 0x78, 0x93, 0xbe, 0x7d, 0xeb, 0xe1, 0x8f, 0x62, 0x4b, 0x9b,
    0x25, 0xf6, 0x09, 0xd0, 0xde, 0x8b, 0x5c, 0xbf, 0x8f, 0x53, 0xba, 0x60, 0xe8, 0xb7, 0x0c, 0x2f
};

static int
run_ecdh_test(void)
{
    /* Convert LE vectors to big-endian for uECC external API.
     * uECC_decompress and uECC_shared_secret use bytesToNative (BE→native LE)
     * for inputs and nativeToBytes (native LE→BE) for outputs. */
    uint8_t compressed[1 + 32];
    uint8_t g_y_full[64];
    uint8_t x_priv_be[32];
    uint8_t gxy_x_be[32];
    for(int i = 0; i < 32; i++) {
        compressed[1 + i] = rfc9528_gy_x[31 - i];  /* LE→BE */
        x_priv_be[i]      = rfc9528_x_priv[31 - i]; /* LE→BE */
        gxy_x_be[i]       = rfc9528_gxy_x[31 - i];  /* LE→BE expected output */
    }
    compressed[0] = 0x03;
    uECC_decompress(compressed, g_y_full, uECC_secp256r1());

    /* Compute shared secret */
    uint8_t shared[32];
    int ok = uECC_shared_secret(g_y_full, x_priv_be, shared, uECC_secp256r1());
    if(!ok) {
        LOG_ERR("ECDH RFC9528 FAIL: uECC_shared_secret returned 0\n");
        return 0;
    }

    /* Compare x-coordinate (both shared and gxy_x_be are big-endian) */
    for(int i = 0; i < 32; i++) {
        if(shared[i] != gxy_x_be[i]) {
            LOG_ERR("ECDH RFC9528 FAIL at byte[%d]: got 0x%02x expected 0x%02x\n",
                    i, shared[i], gxy_x_be[i]);
            return 0;
        }
    }
    LOG_INFO("ECDH RFC9528 test vectors PASS\n");
    return 1;
}

static int
run_keygen_test(void)
{
    uint8_t pub[64], priv[32];
    /* Use a fixed "random" private key scalar to get deterministic output */
    static const uint8_t fixed_scalar[32] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    /* scalar=1: public key should be the base point G */
    (void)fixed_scalar;

    /* Generate a key pair using the CSPRNG (non-deterministic).
     * Then verify the public key validates via uECC_valid_public_key. */
    int ok = uECC_make_key(pub, priv, uECC_secp256r1());
    if(!ok) {
        LOG_ERR("KEYGEN FAIL: uECC_make_key returned 0\n");
        return 0;
    }

    /* Verify the generated public key lies on the P-256 curve */
    ok = uECC_valid_public_key(pub, uECC_secp256r1());
    if(!ok) {
        LOG_ERR("KEYGEN FAIL: generated public key not on curve\n");
        LOG_ERR("pub_x: %02x%02x%02x%02x...\n", pub[0],pub[1],pub[2],pub[3]);
        return 0;
    }

    /* Compute ECDH of (pub, priv) = priv * pub = priv * priv * G = priv^2 * G
     * This exercises mmod_fast_secp256r1 (modular reduction after multiply). */
    uint8_t shared[32];
    ok = uECC_shared_secret(pub, priv, shared, uECC_secp256r1());
    if(!ok) {
        LOG_ERR("KEYGEN FAIL: uECC_shared_secret returned 0\n");
        return 0;
    }

    /* Verify shared secret is also a valid x-coordinate (can't easily compute
     * expected without a reference, so just log it and verify non-zero). */
    int nonzero = 0;
    for(int i = 0; i < 32; i++) nonzero |= shared[i];
    if(!nonzero) {
        LOG_ERR("KEYGEN FAIL: shared secret is all zeros (wrong!)\n");
        return 0;
    }

    LOG_INFO("KEYGEN+ECDH self-consistency PASS (pub on curve, shared != 0)\n");
    return 1;
}

static int
run_case(const char *name,
         const uint32_t *a, const uint32_t *b,
         const uint32_t *expected)
{
    uint32_t result[16];
    uECC_vli_mult(result, a, b, 8);

    for(int i = 0; i < 16; i++) {
        if(result[i] != expected[i]) {
            LOG_ERR("%s FAIL at word[%d]: got 0x%08lx expected 0x%08lx\n",
                    name, i, (unsigned long)result[i],
                    (unsigned long)expected[i]);
            return 0;
        }
    }
    LOG_INFO("%s PASS\n", name);
    return 1;
}

/******************************************************************************/
PROCESS(uecc_mult_test, "uECC vli_mult test");
AUTOSTART_PROCESSES(&uecc_mult_test);
/******************************************************************************/
PROCESS_THREAD(uecc_mult_test, ev, data)
{
    PROCESS_BEGIN();

    LOG_INFO("=== uECC_vli_mult correctness test ===\n");
    LOG_INFO("uECC_OPTIMIZATION_LEVEL=%d\n", uECC_OPTIMIZATION_LEVEL);

    int all_pass = 1;
    all_pass &= run_case("case1 (1*1)",              case1_a, case1_b, case1_expected);
    all_pass &= run_case("case2 (0xFFFF*0xFFFF)",    case2_a, case2_b, case2_expected);
    all_pass &= run_case("case3 (multi-word)",       case3_a, case3_b, case3_expected);
    all_pass &= run_case("case4 (random 256-bit)",  case4_a, case4_b, case4_expected);
    /* Test uECC_vli_add: carry propagation across ALL 8 words */
    {
        /* a=[0xFFFFFFFF,0,0,0,0,0,0,0], b=[1,0,0,0,0,0,0,0]
         * → carry into word[1]: result=[0,1,0,0,0,0,0,0], carry=0 */
        static const uint32_t va[8] = { 0xFFFFFFFF,0,0,0,0,0,0,0 };
        static const uint32_t vb[8] = { 1,0,0,0,0,0,0,0 };
        static const uint32_t ve[8] = { 0,1,0,0,0,0,0,0 };
        uint32_t vr[8];
        uECC_word_t carry = uECC_vli_add(vr, va, vb, 8);
        int ok = (carry == 0);
        for(int i = 0; i < 8 && ok; i++) ok = (vr[i] == ve[i]);
        if(ok) LOG_INFO("uECC_vli_add carry-prop PASS\n");
        else { LOG_ERR("uECC_vli_add carry-prop FAIL: carry=%d r[0]=0x%lx r[1]=0x%lx\n",
                        (int)carry, (unsigned long)vr[0], (unsigned long)vr[1]); all_pass = 0; }
    }
    {
        /* a=[0xFF..FF,0xFF..FF,...,0xFF..FF] (all words), b=[1,0..0]
         * → carry propagates through all 8 words: result=[0,0..0], carry=1 */
        static const uint32_t va[8] = { 0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
                                         0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF };
        static const uint32_t vb[8] = { 1, 0, 0, 0, 0, 0, 0, 0 };
        uint32_t vr[8];
        uECC_word_t carry = uECC_vli_add(vr, va, vb, 8);
        int ok = (carry == 1);
        for(int i = 0; i < 8 && ok; i++) ok = (vr[i] == 0);
        if(ok) LOG_INFO("uECC_vli_add overflow PASS\n");
        else { LOG_ERR("uECC_vli_add overflow FAIL carry=%d result[0]=0x%08lx\n", (int)carry, (unsigned long)vr[0]); all_pass = 0; }
    }

    /* Test uECC_vli_add with result==left==right (self-addition as in mmod) */
    {
        /* mmod calls: carry = uECC_vli_add(tmp, tmp, tmp, 8) — doubles tmp */
        uint32_t tmp[8] = { 3, 5, 7, 11, 13, 17, 19, 23 };
        uint32_t expected[8] = { 6, 10, 14, 22, 26, 34, 38, 46 };
        uECC_word_t carry = uECC_vli_add(tmp, tmp, tmp, 8);
        int ok = (carry == 0);
        for(int i = 0; i < 8 && ok; i++) ok = (tmp[i] == expected[i]);
        if(ok) LOG_INFO("uECC_vli_add self (r==l==r) PASS\n");
        else { LOG_ERR("uECC_vli_add self FAIL: carry=%d tmp[0]=0x%lx exp=0x%lx\n",
                        (int)carry, (unsigned long)tmp[0], (unsigned long)expected[0]); all_pass = 0; }
    }

    /* Test uECC_vli_sub with borrow propagation */
    {
        /* a=[2,1,0..0], b=[3,0..0] → a-b needs borrow: result=[0xFFFF..FF,0,0..0], borrow=0
         * Actually: a=[2,1,0..0] = 1*2^32 + 2, b=[3,0..0] = 3.
         * a-b = 1*2^32 + 2 - 3 = 1*2^32 - 1 = [0xFFFFFFFF, 0, ...] (no borrow) */
        uint32_t va[8] = { 2, 1, 0, 0, 0, 0, 0, 0 };
        uint32_t vb[8] = { 3, 0, 0, 0, 0, 0, 0, 0 };
        uint32_t ve[8] = { 0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0 };
        uint32_t vr[8];
        uECC_word_t borrow = uECC_vli_sub(vr, va, vb, 8);
        int ok = (borrow == 0);
        for(int i = 0; i < 8 && ok; i++) ok = (vr[i] == ve[i]);
        if(ok) LOG_INFO("uECC_vli_sub borrow-prop PASS\n");
        else { LOG_ERR("uECC_vli_sub borrow-prop FAIL: borrow=%d r[0]=0x%lx r[1]=0x%lx\n",
                        (int)borrow, (unsigned long)vr[0], (unsigned long)vr[1]); all_pass = 0; }
    }
    {
        /* a=[3,0..0] - b=[4,0..0] → underflow, borrow=1 */
        uint32_t va[8] = { 3, 0, 0, 0, 0, 0, 0, 0 };
        uint32_t vb[8] = { 4, 0, 0, 0, 0, 0, 0, 0 };
        /* 3 - 4 = -1 = 0xFFFF...FF (all ones), borrow=1 */
        uint32_t vr[8];
        uECC_word_t borrow = uECC_vli_sub(vr, va, vb, 8);
        int ok = (borrow == 1);
        for(int i = 0; i < 8 && ok; i++) ok = (vr[i] == 0xFFFFFFFFu);
        if(ok) LOG_INFO("uECC_vli_sub underflow PASS\n");
        else { LOG_ERR("uECC_vli_sub underflow FAIL: borrow=%d r[0]=0x%lx\n",
                        (int)borrow, (unsigned long)vr[0]); all_pass = 0; }
    }

    /* Test vli_mmod_fast_secp256r1 via uECC_vli_mmod_fast:
     * (p-1)^2 mod p should equal 1.
     * p-1 in little-endian uint32_t words:
     * [0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
     *  0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF] */
    {
        static const uECC_word_t pm1[8] = {
            0xFFFFFFFEu, 0xFFFFFFFFu, 0xFFFFFFFFu, 0x00000000u,
            0x00000000u, 0x00000000u, 0x00000001u, 0xFFFFFFFFu
        };
        uECC_word_t product[16], result[8];
        uECC_vli_mult(product, pm1, pm1, 8);
        uECC_vli_mmod_fast(result, product, uECC_secp256r1());
        /* (p-1)^2 mod p = 1 → result = [1, 0, 0, 0, 0, 0, 0, 0] */
        int ok = (result[0] == 1);
        for(int i = 1; i < 8 && ok; i++) ok = (result[i] == 0);
        if(ok) LOG_INFO("mmod_fast (p-1)^2 mod p = 1 PASS\n");
        else { LOG_ERR("mmod_fast (p-1)^2 mod p FAIL: result[0]=0x%08lx\n", (unsigned long)result[0]); all_pass = 0; }
    }

    /* Test P-256 base point G is valid (exercises modular arithmetic) */
    {
        /* P-256 base point G, big-endian byte format (uECC external API format):
         * x_BE = 6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
         * y_BE = 4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5 */
        static const uint8_t G_pub[64] = {
            /* x, BE: */ 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47,
            0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2, 0x77, 0x03,
            0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96,
            /* y, BE: */ 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
            0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce,
            0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68,
            0x37, 0xbf, 0x51, 0xf5
        };
        int valid = uECC_valid_public_key(G_pub, uECC_secp256r1());
        if(valid) {
            LOG_INFO("P-256 base point G is valid PASS\n");
        } else {
            LOG_ERR("P-256 base point G FAIL: modular arithmetic wrong\n");
            all_pass = 0;
        }
    }

    all_pass &= run_sha256_sigma_test();
    all_pass &= run_sha256_msch_diagnostic();
    all_pass &= run_sha256_test();
    /* Test uECC_vli_square: should equal uECC_vli_mult(a, a) */
    {
        uint32_t sq_via_mult[16], sq_via_square[16];
        uECC_vli_mult(sq_via_mult, case4_a, case4_a, 8);
        uECC_vli_square(sq_via_square, case4_a, 8);
        int sq_ok = 1;
        for(int i = 0; i < 16; i++) {
            if(sq_via_square[i] != sq_via_mult[i]) {
                LOG_ERR("uECC_vli_square FAIL at word[%d]: square=0x%08lx mult=0x%08lx\n",
                        i, (unsigned long)sq_via_square[i], (unsigned long)sq_via_mult[i]);
                sq_ok = 0; break;
            }
        }
        if(sq_ok) LOG_INFO("uECC_vli_square matches vli_mult PASS\n");
        all_pass &= sq_ok;
    }
    all_pass &= run_ecdh_test();
    all_pass &= run_keygen_test();

    if(all_pass) {
        LOG_INFO("ALL TESTS PASSED\n");
    } else {
        LOG_ERR("SOME TESTS FAILED\n");
    }

    PROCESS_END();
}
