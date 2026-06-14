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
 * @file ed25519_verify.c
 * @brief Minimal from-scratch RFC 8032 Ed25519 (PureEdDSA) signature verifier.
 *
 * Implements RFC 8032 §5.1.7 signature verification entirely from scratch:
 * field arithmetic modulo 2^255-19 using the "ref10" 25.5-bit limb
 * representation from SUPERCOP (10 limbs, alternating 26/25 bits), Edwards25519
 * curve point operations (decode, add, double, scalar multiply), and scalar
 * reduction modulo the group order `l`. SHA-512 is provided by mbedTLS.
 *
 * Used by the C509 service (crypto_mbedtls.c) to verify Ed25519-signed C509
 * certificates, since mbedTLS does not provide a directly usable Ed25519
 * verification primitive in this build configuration.
 */

#include "ed25519_verify.h"
#include <mbedtls/sha512.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

/* ── Field element: 10 limbs, alternating 26/25 bit capacity ──────────────── */

typedef int32_t fe[10];

static void fe_0(fe h) { memset(h, 0, sizeof(int32_t) * 10); }
static void fe_1(fe h) { fe_0(h); h[0] = 1; }

static void fe_copy(fe h, const fe f) {
    int i;
    for (i = 0; i < 10; i++) h[i] = f[i];
}

static void fe_add(fe h, const fe f, const fe g) {
    int i;
    for (i = 0; i < 10; i++) h[i] = f[i] + g[i];
}

static void fe_sub(fe h, const fe f, const fe g) {
    int i;
    for (i = 0; i < 10; i++) h[i] = f[i] - g[i];
}

static void fe_neg(fe h, const fe f) {
    int i;
    for (i = 0; i < 10; i++) h[i] = -f[i];
}

/**
 * @brief Decode a 32-byte little-endian field element into 10 ref10 limbs.
 *
 * Splits the 256-bit input into limbs of alternating 26/25 bits at the exact
 * bit offsets used by the ref10 representation, then performs an initial
 * carry/reduction pass so every limb fits its nominal bit width and the value
 * is congruent to the input mod 2^255-19. Getting the per-limb bit-shift and
 * mask boundaries exactly right here is critical: an off-by-one in any shift
 * silently corrupts the decoded field element (this was the source of one of
 * the subtle bugs fixed in this file).
 */
static void fe_frombytes(fe h, const uint8_t *s) {
    /* ref10 limb layout: alternating 26/25-bit limbs, bit-exact boundaries.
     * h[i] start bits: 0, 26, 51, 77, 102, 128, 153, 179, 204, 230 */
    int64_t h0 = (int64_t)(s[0])
               | (int64_t)(s[1]) << 8
               | (int64_t)(s[2]) << 16
               | ((int64_t)(s[3] & 0x03)) << 24;      /* bits   0-25  (26) */
    int64_t h1 = (int64_t)(s[3] >> 2)
               | (int64_t)(s[4]) << 6
               | (int64_t)(s[5]) << 14
               | ((int64_t)(s[6] & 0x07)) << 22;      /* bits  26-50  (25) */
    int64_t h2 = (int64_t)(s[6] >> 3)
               | (int64_t)(s[7]) << 5
               | (int64_t)(s[8]) << 13
               | ((int64_t)(s[9] & 0x1f)) << 21;      /* bits  51-76  (26) */
    int64_t h3 = (int64_t)(s[9] >> 5)
               | (int64_t)(s[10]) << 3
               | (int64_t)(s[11]) << 11
               | ((int64_t)(s[12] & 0x3f)) << 19;     /* bits  77-101 (25) */
    int64_t h4 = (int64_t)(s[12] >> 6)
               | (int64_t)(s[13]) << 2
               | (int64_t)(s[14]) << 10
               | (int64_t)(s[15]) << 18;              /* bits 102-127 (26) */
    int64_t h5 = (int64_t)(s[16])
               | (int64_t)(s[17]) << 8
               | (int64_t)(s[18]) << 16
               | ((int64_t)(s[19] & 0x01)) << 24;     /* bits 128-152 (25) */
    int64_t h6 = (int64_t)(s[19] >> 1)
               | (int64_t)(s[20]) << 7
               | (int64_t)(s[21]) << 15
               | ((int64_t)(s[22] & 0x07)) << 23;     /* bits 153-178 (26) */
    int64_t h7 = (int64_t)(s[22] >> 3)
               | (int64_t)(s[23]) << 5
               | (int64_t)(s[24]) << 13
               | ((int64_t)(s[25] & 0x0f)) << 21;     /* bits 179-203 (25) */
    int64_t h8 = (int64_t)(s[25] >> 4)
               | (int64_t)(s[26]) << 4
               | (int64_t)(s[27]) << 12
               | ((int64_t)(s[28] & 0x3f)) << 20;     /* bits 204-229 (26) */
    int64_t h9 = (int64_t)(s[28] >> 6)
               | (int64_t)(s[29]) << 2
               | (int64_t)(s[30]) << 10
               | ((int64_t)(s[31] & 0x7f)) << 18;     /* bits 230-254 (25) */

    /* Reduce */
    int64_t carry9 = (h9 + (1 << 24)) >> 25; h0 += carry9 * 19; h9 -= carry9 << 25;
    int64_t carry1 = (h1 + (1 << 24)) >> 25; h2 += carry1; h1 -= carry1 << 25;
    int64_t carry3 = (h3 + (1 << 24)) >> 25; h4 += carry3; h3 -= carry3 << 25;
    int64_t carry5 = (h5 + (1 << 24)) >> 25; h6 += carry5; h5 -= carry5 << 25;
    int64_t carry7 = (h7 + (1 << 24)) >> 25; h8 += carry7; h7 -= carry7 << 25;
    int64_t carry0 = (h0 + (1 << 25)) >> 26; h1 += carry0; h0 -= carry0 << 26;
    int64_t carry2 = (h2 + (1 << 25)) >> 26; h3 += carry2; h2 -= carry2 << 26;
    int64_t carry4 = (h4 + (1 << 25)) >> 26; h5 += carry4; h4 -= carry4 << 26;
    int64_t carry6 = (h6 + (1 << 25)) >> 26; h7 += carry6; h6 -= carry6 << 26;
    int64_t carry8 = (h8 + (1 << 25)) >> 26; h9 += carry8; h8 -= carry8 << 26;

    h[0]=(int32_t)h0; h[1]=(int32_t)h1; h[2]=(int32_t)h2; h[3]=(int32_t)h3;
    h[4]=(int32_t)h4; h[5]=(int32_t)h5; h[6]=(int32_t)h6; h[7]=(int32_t)h7;
    h[8]=(int32_t)h8; h[9]=(int32_t)h9;
}

/**
 * @brief Encode a ref10 field element as 32 little-endian bytes, fully reduced mod p.
 *
 * Limbs can carry small positive or negative excesses after arithmetic ops,
 * so before serializing we must (1) compute how many copies of p=2^255-19
 * to subtract so the value lands in [0, p), and (2) propagate carries so
 * every limb is back within its nominal 26/25-bit range.
 *
 * The first carry-propagation pass below only touches limbs 0-8 (c0..c8);
 * limb 9 (c9) is handled as a final, separate "carry9" step that masks
 * limb 9 back down to its 25-bit range. The full reduction (the q
 * computation and `t[0] += 19*q` above) guarantees limb 9 has no leftover
 * bits to carry out by this point, so carry9 only needs to clear any stray
 * high bits left by the c0..c8 propagation — but without it those stray
 * bits leak into the top byte of the encoded output. A missing carry9 step
 * was one of the subtle bugs fixed in this file.
 */
static void fe_tobytes(uint8_t *s, const fe h) {
    int32_t t[10];
    fe_copy(t, h);
    /* Fully reduce mod p */
    int32_t q = (19 * t[9] + (1 << 24)) >> 25;
    q = (t[0] + q) >> 26; q = (t[1] + q) >> 25; q = (t[2] + q) >> 26;
    q = (t[3] + q) >> 25; q = (t[4] + q) >> 26; q = (t[5] + q) >> 25;
    q = (t[6] + q) >> 26; q = (t[7] + q) >> 25; q = (t[8] + q) >> 26;
    q = (t[9] + q) >> 25;
    t[0] += 19 * q;
    int32_t c0 = t[0] >> 26; t[1] += c0; t[0] -= c0 << 26;
    int32_t c1 = t[1] >> 25; t[2] += c1; t[1] -= c1 << 25;
    int32_t c2 = t[2] >> 26; t[3] += c2; t[2] -= c2 << 26;
    int32_t c3 = t[3] >> 25; t[4] += c3; t[3] -= c3 << 25;
    int32_t c4 = t[4] >> 26; t[5] += c4; t[4] -= c4 << 26;
    int32_t c5 = t[5] >> 25; t[6] += c5; t[5] -= c5 << 25;
    int32_t c6 = t[6] >> 26; t[7] += c6; t[6] -= c6 << 26;
    int32_t c7 = t[7] >> 25; t[8] += c7; t[7] -= c7 << 25;
    int32_t c8 = t[8] >> 26; t[9] += c8; t[8] -= c8 << 26;
    /* carry9: final mask of limb 9 down to 25 bits. p was already
     * conditionally subtracted above via q, so this just clears any stray
     * high bit rather than wrapping back around mod p. */
    int32_t c9 = t[9] >> 25; t[9] -= c9 << 25;
    s[0]  = (uint8_t)(t[0]);
    s[1]  = (uint8_t)(t[0] >> 8);
    s[2]  = (uint8_t)(t[0] >> 16);
    s[3]  = (uint8_t)((t[0] >> 24) | (t[1] << 2));
    s[4]  = (uint8_t)(t[1] >> 6);
    s[5]  = (uint8_t)(t[1] >> 14);
    s[6]  = (uint8_t)((t[1] >> 22) | (t[2] << 3));
    s[7]  = (uint8_t)(t[2] >> 5);
    s[8]  = (uint8_t)(t[2] >> 13);
    s[9]  = (uint8_t)((t[2] >> 21) | (t[3] << 5));
    s[10] = (uint8_t)(t[3] >> 3);
    s[11] = (uint8_t)(t[3] >> 11);
    s[12] = (uint8_t)((t[3] >> 19) | (t[4] << 6));
    s[13] = (uint8_t)(t[4] >> 2);
    s[14] = (uint8_t)(t[4] >> 10);
    s[15] = (uint8_t)(t[4] >> 18);
    s[16] = (uint8_t)(t[5]);
    s[17] = (uint8_t)(t[5] >> 8);
    s[18] = (uint8_t)(t[5] >> 16);
    s[19] = (uint8_t)((t[5] >> 24) | (t[6] << 1));
    s[20] = (uint8_t)(t[6] >> 7);
    s[21] = (uint8_t)(t[6] >> 15);
    s[22] = (uint8_t)((t[6] >> 23) | (t[7] << 3));
    s[23] = (uint8_t)(t[7] >> 5);
    s[24] = (uint8_t)(t[7] >> 13);
    s[25] = (uint8_t)((t[7] >> 21) | (t[8] << 4));
    s[26] = (uint8_t)(t[8] >> 4);
    s[27] = (uint8_t)(t[8] >> 12);
    s[28] = (uint8_t)((t[8] >> 20) | (t[9] << 6));
    s[29] = (uint8_t)(t[9] >> 2);
    s[30] = (uint8_t)(t[9] >> 10);
    s[31] = (uint8_t)(t[9] >> 18);
}

static int fe_isnegative(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    return s[0] & 1;
}

static int fe_isnonzero(const fe f) {
    uint8_t s[32];
    fe_tobytes(s, f);
    uint8_t acc = 0;
    int i;
    for (i = 0; i < 32; i++) acc |= s[i];
    return acc != 0;
}

static void fe_mul(fe h, const fe f, const fe g) {
    int64_t f0=f[0],f1=f[1],f2=f[2],f3=f[3],f4=f[4];
    int64_t f5=f[5],f6=f[6],f7=f[7],f8=f[8],f9=f[9];
    int64_t g0=g[0],g1=g[1],g2=g[2],g3=g[3],g4=g[4];
    int64_t g5=g[5],g6=g[6],g7=g[7],g8=g[8],g9=g[9];
    int64_t g1_19=19*g1,g2_19=19*g2,g3_19=19*g3,g4_19=19*g4;
    int64_t g5_19=19*g5,g6_19=19*g6,g7_19=19*g7,g8_19=19*g8,g9_19=19*g9;
    int64_t f1_2=2*f1,f3_2=2*f3,f5_2=2*f5,f7_2=2*f7,f9_2=2*f9;

    int64_t h0=f0*g0+f1_2*g9_19+f2*g8_19+f3_2*g7_19+f4*g6_19+f5_2*g5_19+f6*g4_19+f7_2*g3_19+f8*g2_19+f9_2*g1_19;
    int64_t h1=f0*g1+f1*g0+f2*g9_19+f3*g8_19+f4*g7_19+f5*g6_19+f6*g5_19+f7*g4_19+f8*g3_19+f9*g2_19;
    int64_t h2=f0*g2+f1_2*g1+f2*g0+f3_2*g9_19+f4*g8_19+f5_2*g7_19+f6*g6_19+f7_2*g5_19+f8*g4_19+f9_2*g3_19;
    int64_t h3=f0*g3+f1*g2+f2*g1+f3*g0+f4*g9_19+f5*g8_19+f6*g7_19+f7*g6_19+f8*g5_19+f9*g4_19;
    int64_t h4=f0*g4+f1_2*g3+f2*g2+f3_2*g1+f4*g0+f5_2*g9_19+f6*g8_19+f7_2*g7_19+f8*g6_19+f9_2*g5_19;
    int64_t h5=f0*g5+f1*g4+f2*g3+f3*g2+f4*g1+f5*g0+f6*g9_19+f7*g8_19+f8*g7_19+f9*g6_19;
    int64_t h6=f0*g6+f1_2*g5+f2*g4+f3_2*g3+f4*g2+f5_2*g1+f6*g0+f7_2*g9_19+f8*g8_19+f9_2*g7_19;
    int64_t h7=f0*g7+f1*g6+f2*g5+f3*g4+f4*g3+f5*g2+f6*g1+f7*g0+f8*g9_19+f9*g8_19;
    int64_t h8=f0*g8+f1_2*g7+f2*g6+f3_2*g5+f4*g4+f5_2*g3+f6*g2+f7_2*g1+f8*g0+f9_2*g9_19;
    int64_t h9=f0*g9+f1*g8+f2*g7+f3*g6+f4*g5+f5*g4+f6*g3+f7*g2+f8*g1+f9*g0;

    int64_t c0,c1,c2,c3,c4,c5,c6,c7,c8,c9;
    c0=(h0+(1LL<<25))>>26; h1+=c0; h0-=c0<<26;
    c4=(h4+(1LL<<25))>>26; h5+=c4; h4-=c4<<26;
    c1=(h1+(1LL<<24))>>25; h2+=c1; h1-=c1<<25;
    c5=(h5+(1LL<<24))>>25; h6+=c5; h5-=c5<<25;
    c2=(h2+(1LL<<25))>>26; h3+=c2; h2-=c2<<26;
    c6=(h6+(1LL<<25))>>26; h7+=c6; h6-=c6<<26;
    c3=(h3+(1LL<<24))>>25; h4+=c3; h3-=c3<<25;
    c7=(h7+(1LL<<24))>>25; h8+=c7; h7-=c7<<25;
    c4=(h4+(1LL<<25))>>26; h5+=c4; h4-=c4<<26;
    c8=(h8+(1LL<<25))>>26; h9+=c8; h8-=c8<<26;
    c9=(h9+(1LL<<24))>>25; h0+=c9*19; h9-=c9<<25;
    c0=(h0+(1LL<<25))>>26; h1+=c0; h0-=c0<<26;

    h[0]=(int32_t)h0; h[1]=(int32_t)h1; h[2]=(int32_t)h2; h[3]=(int32_t)h3;
    h[4]=(int32_t)h4; h[5]=(int32_t)h5; h[6]=(int32_t)h6; h[7]=(int32_t)h7;
    h[8]=(int32_t)h8; h[9]=(int32_t)h9;
}

static void fe_sq(fe h, const fe f) { fe_mul(h, f, f); }

/* Computes f^(2^252-3) via the standard chain for p^((p-5)/8) used in sqrt. */
static void fe_pow22523(fe out, const fe z) {
    fe t0, t1, t2;
    int i;
    fe_sq(t0, z);
    fe_sq(t1, t0); fe_sq(t1, t1);
    fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t0, t0);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 5; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 10; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 20; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 10; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t1, t0);
    for (i = 1; i < 50; i++) fe_sq(t1, t1);
    fe_mul(t1, t1, t0);
    fe_sq(t2, t1);
    for (i = 1; i < 100; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1);
    for (i = 1; i < 50; i++) fe_sq(t1, t1);
    fe_mul(t0, t1, t0);
    fe_sq(t0, t0); fe_sq(t0, t0);
    fe_mul(out, t0, z);
}

/* ── Edwards curve point (extended coordinates: X, Y, Z, T) ─────────────── */

typedef struct { fe X, Y, Z, T; } ge_p3;
typedef struct { fe X, Y, Z; }    ge_p2;

/* d = -121665/121666 mod p (the twist constant for Edwards25519) */
static const fe d = {
    -10913610, 13857413, -15372611, 6949391, 114729,
    -8787816, -6275908, -3247719, -18696448, -12055116
};
/* 2*d */
static const fe d2 = {
    -21827239, -5839606, -30745221, 13898782, 229458,
    15978800, -12551817, -6495438, 29715968, 9444199
};
/* sqrt(-1) mod p */
static const fe sqrtm1 = {
    -32595792, -7943725, 9377950, 3500415, 12389472,
    -272473, -25146209, -2005654, 326686, 11406482
};
/**
 * @brief The Edwards25519 base point B in extended (X,Y,Z,T) coordinates.
 *
 * Defined by RFC 8032 as y = 4/5 mod p with x chosen as the unique root with
 * even sign (the "positive" root). Z=1 and T=X*Y/Z=X*Y for the affine
 * embedding into extended coordinates. These limb values are the ref10
 * encoding of that fixed point and must match the reference exactly bit-for-
 * bit; garbled constants here (as was the case in an earlier version of this
 * file) silently produce a curve point that is *not* the real base point, so
 * every scalar multiplication against B yields wrong results without any
 * obvious error.
 */
static const ge_p3 B = {
    {-14297830,-7645148,16144683,-16471763,27570974,-2696100,-26142465,8378389,20764389,8758491},
    {-26843541,-6710886,13421773,-13421773,26843546,6710886,-13421773,13421773,-26843546,-6710886},
    {1,0,0,0,0,0,0,0,0,0},
    {28827062,-6116119,-27349572,244363,8635006,11264893,19351346,13413597,16611511,-6414980}
};

/* fe_invert using SUPERCOP chain */
static void fe_invert(fe out, const fe z) {
    fe t0, t1, t2, t3;
    int i;
    fe_sq(t0, z);
    fe_sq(t1, t0); fe_sq(t1, t1); fe_mul(t1, z, t1);
    fe_mul(t0, t0, t1);
    fe_sq(t2, t0); fe_mul(t1, t1, t2);
    fe_sq(t2, t1);
    for (i = 1; i < 5; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 20; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 10; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t2, t1);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t2, t2, t1);
    fe_sq(t3, t2);
    for (i = 1; i < 100; i++) fe_sq(t3, t3);
    fe_mul(t2, t3, t2);
    fe_sq(t2, t2);
    for (i = 1; i < 50; i++) fe_sq(t2, t2);
    fe_mul(t1, t2, t1);
    fe_sq(t1, t1); fe_sq(t1, t1); fe_sq(t1, t1); fe_sq(t1, t1); fe_sq(t1, t1);
    fe_mul(out, t1, t0);
}

static void ge_p3_to_bytes(uint8_t s[32], const ge_p3 *p) {
    fe recip, x, y;
    fe_invert(recip, p->Z);
    fe_mul(x, p->X, recip);
    fe_mul(y, p->Y, recip);
    fe_tobytes(s, y);
    s[31] ^= (uint8_t)(fe_isnegative(x) << 7);
}

/* Decode compressed point (y || sign_bit) → ge_p3; returns 0 on success */
static int ge_frombytes(ge_p3 *h, const uint8_t *s) {
    fe u, v, v3, vxx, check;
    fe_frombytes(h->Y, s);
    fe_1(h->Z);
    fe_sq(u, h->Y);            /* u = y^2 */
    fe_mul(v, u, d);           /* v = d*y^2 */
    fe_sub(u, u, h->Z);        /* u = y^2 - 1 */
    fe_add(v, v, h->Z);        /* v = d*y^2 + 1 */
    fe_sq(v3, v); fe_mul(v3, v3, v);  /* v3 = v^3 */
    fe_sq(h->X, v3); fe_mul(h->X, h->X, v); fe_mul(h->X, h->X, u);
    fe_pow22523(h->X, h->X);   /* x = (u*v^7)^((p-5)/8) */
    fe_mul(h->X, h->X, v3); fe_mul(h->X, h->X, u); /* x = u*v^3 * (u*v^7)^((p-5)/8) */

    fe_sq(vxx, h->X); fe_mul(vxx, vxx, v);
    fe_sub(check, vxx, u);
    if (fe_isnonzero(check)) {
        fe_mul(h->X, h->X, sqrtm1);
        fe_sq(vxx, h->X); fe_mul(vxx, vxx, v);
        fe_sub(check, vxx, u);
        if (fe_isnonzero(check)) return -1;
    }
    if (fe_isnegative(h->X) != (s[31] >> 7)) fe_neg(h->X, h->X);
    fe_mul(h->T, h->X, h->Y);
    return 0;
}

/* Point addition: r = p + q (mixed: q in precomputed form with Z=1) */
static void ge_add(ge_p3 *r, const ge_p3 *p, const ge_p3 *q) {
    fe A, B, C, D, E, F, G, H;
    fe_sub(A, p->Y, p->X); fe_sub(B, q->Y, q->X); fe_mul(A, A, B);
    fe_add(B, p->Y, p->X); {fe tmp; fe_add(tmp,q->Y,q->X); fe_mul(B,B,tmp);}
    fe_mul(C, p->T, q->T); fe_mul(C, C, d2);
    fe_mul(D, p->Z, q->Z); fe_add(D, D, D); /* D = 2*Z1*Z2 */
    fe_sub(E, B, A);
    fe_sub(F, D, C);
    fe_add(G, D, C);
    fe_add(H, B, A);
    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

/**
 * @brief Point doubling in extended coordinates: r = 2*p.
 *
 * Implements the "dbl-2008-hwcd" doubling formulas specialized for the
 * Edwards curve parameter a=-1 (as used by Ed25519). This dedicated doubling
 * formula is significantly cheaper than computing ge_add(r, p, p), and is
 * used in the inner loop of every scalar multiplication (every bit of the
 * scalar triggers one doubling). An earlier version of this file used an
 * incorrect formula here (wrong combination of A, B, C, E, F, G, H), which
 * produced a curve point that still "looked" like a valid point but did not
 * actually equal 2*p — causing scalar multiplication results to silently
 * diverge from the correct value.
 */
static void ge_p3_dbl(ge_p3 *r, const ge_p3 *p) {
    /* dbl-2008-hwcd with a=-1 (Ed25519) */
    fe A, B, C, E, F, G, H;
    fe_sq(A, p->X);                        /* A = X^2          */
    fe_sq(B, p->Y);                        /* B = Y^2          */
    fe_sq(C, p->Z); fe_add(C, C, C);      /* C = 2*Z^2        */
    fe_add(E, p->X, p->Y); fe_sq(E, E);
    fe_sub(E, E, A); fe_sub(E, E, B);     /* E = 2*X*Y        */
    fe_sub(G, B, A);                       /* G = B-A (=D+B)   */
    fe_sub(F, G, C);                       /* F = G-C          */
    fe_add(H, A, B); fe_neg(H, H);        /* H = -(A+B) (=D-B)*/
    fe_mul(r->X, E, F);
    fe_mul(r->Y, G, H);
    fe_mul(r->T, E, H);
    fe_mul(r->Z, F, G);
}

/* Scalar multiplication: r = s * B (base point) using double-and-add */
static void ge_scalarmult_base(ge_p3 *r, const uint8_t s[32]) {
    ge_p3 Q;
    /* Start with identity: (0, 1, 1, 0) in extended coords */
    fe_0(r->X); fe_1(r->Y); fe_1(r->Z); fe_0(r->T);
    fe_copy(Q.X, B.X); fe_copy(Q.Y, B.Y); fe_copy(Q.Z, B.Z); fe_copy(Q.T, B.T);
    int i;
    for (i = 0; i < 256; i++) {
        int bit = (s[i >> 3] >> (i & 7)) & 1;
        ge_p3 sum;
        ge_add(&sum, r, &Q);
        /* Conditionally select: if bit, r = sum; else r = r */
        int j;
        for (j = 0; j < 10; j++) {
            int32_t diff;
            diff = sum.X[j] ^ r->X[j]; r->X[j] ^= (int32_t)(-(int32_t)bit & diff);
            diff = sum.Y[j] ^ r->Y[j]; r->Y[j] ^= (int32_t)(-(int32_t)bit & diff);
            diff = sum.Z[j] ^ r->Z[j]; r->Z[j] ^= (int32_t)(-(int32_t)bit & diff);
            diff = sum.T[j] ^ r->T[j]; r->T[j] ^= (int32_t)(-(int32_t)bit & diff);
        }
        ge_p3_dbl(&Q, &Q);
    }
}

/* Double scalar multiplication: r = [a]B + [b]A (variable time is fine for verify) */
static void ge_double_scalarmult_vartime(ge_p3 *r, const uint8_t a[32],
                                         const ge_p3 *A, const uint8_t b[32]) {
    ge_p3 Acopy;
    fe_copy(Acopy.X, A->X); fe_copy(Acopy.Y, A->Y);
    fe_copy(Acopy.Z, A->Z); fe_copy(Acopy.T, A->T);

    ge_p3 aB, bA;
    ge_scalarmult_base(&aB, a);

    /* Scalar multiply [b]A using the same simple method */
    fe_0(bA.X); fe_1(bA.Y); fe_1(bA.Z); fe_0(bA.T);
    ge_p3 Q2;
    fe_copy(Q2.X, Acopy.X); fe_copy(Q2.Y, Acopy.Y);
    fe_copy(Q2.Z, Acopy.Z); fe_copy(Q2.T, Acopy.T);
    int i;
    for (i = 0; i < 256; i++) {
        int bit = (b[i >> 3] >> (i & 7)) & 1;
        ge_p3 sum;
        ge_add(&sum, &bA, &Q2);
        int j;
        for (j = 0; j < 10; j++) {
            int32_t diff;
            diff = sum.X[j] ^ bA.X[j]; bA.X[j] ^= (int32_t)(-(int32_t)bit & diff);
            diff = sum.Y[j] ^ bA.Y[j]; bA.Y[j] ^= (int32_t)(-(int32_t)bit & diff);
            diff = sum.Z[j] ^ bA.Z[j]; bA.Z[j] ^= (int32_t)(-(int32_t)bit & diff);
            diff = sum.T[j] ^ bA.T[j]; bA.T[j] ^= (int32_t)(-(int32_t)bit & diff);
        }
        ge_p3_dbl(&Q2, &Q2);
    }

    ge_add(r, &aB, &bA);
}

/* ── Scalar arithmetic mod group order l ─────────────────────────────────── */

/* l = 2^252 + 27742317777372353535851937790883648493 */
static const uint8_t l[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7,
    0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
};

/* Check s < l (RFC 8032 §5.1.7 step 2) */
static int sc_check(const uint8_t *s) {
    int i;
    for (i = 31; i >= 0; i--) {
        if (s[i] > l[i]) return 0; /* s > l: invalid */
        if (s[i] < l[i]) return 1; /* s < l: valid */
    }
    return 0; /* s == l: invalid */
}

/**
 * @brief Reduce a 512-bit little-endian value mod the group order `l`.
 *
 * Used to compute k = SHA-512(R || A || msg) mod l in step 3 of RFC 8032
 * §5.1.7. Rather than the highly-optimized limb-based reduction used by
 * ref10 (which relies on precomputed multiples of l in a packed limb
 * format), this is a straightforward binary long division: l is left-shifted
 * into alignment with the most-significant bit of the remainder and
 * conditionally subtracted, one bit position at a time, working down from
 * the top. l has 253 significant bits and h64 has at most 512, so at most
 * 512-253 = 259 shift positions are needed (`shift` runs from 259 down to 0).
 * This is much slower than the ref10 approach but is simple, easy to verify
 * for correctness, and reduction only happens once per signature
 * verification. An earlier version of this function was broken (incorrect
 * shift/compare/subtract logic) and produced a `k` that did not actually
 * satisfy `k == h64 mod l`, causing all signature verifications to fail.
 */
static void sc_reduce(uint8_t out[32], const uint8_t h64[64]) {
    uint32_t r[16], lw[8];
    int i, shift;

    for (i = 0; i < 16; i++) {
        r[i] = (uint32_t)h64[4*i] | ((uint32_t)h64[4*i+1] << 8)
             | ((uint32_t)h64[4*i+2] << 16) | ((uint32_t)h64[4*i+3] << 24);
    }
    for (i = 0; i < 8; i++) {
        lw[i] = (uint32_t)l[4*i] | ((uint32_t)l[4*i+1] << 8)
              | ((uint32_t)l[4*i+2] << 16) | ((uint32_t)l[4*i+3] << 24);
    }

    for (shift = 259; shift >= 0; shift--) {
        uint32_t shifted[16] = {0};
        int word_shift = shift / 32;
        int bit_shift = shift % 32;
        int ge;

        for (i = 0; i < 8; i++) {
            int dst = i + word_shift;
            if (dst < 16) {
                shifted[dst] |= (bit_shift == 0) ? lw[i] : (lw[i] << bit_shift);
            }
            if (bit_shift != 0 && dst + 1 < 16) {
                shifted[dst+1] |= (uint32_t)((uint64_t)lw[i] >> (32 - bit_shift));
            }
        }

        ge = 1;
        for (i = 15; i >= 0; i--) {
            if (r[i] != shifted[i]) { ge = (r[i] > shifted[i]); break; }
        }
        if (ge) {
            int64_t borrow = 0;
            for (i = 0; i < 16; i++) {
                int64_t diff = (int64_t)r[i] - (int64_t)shifted[i] - borrow;
                if (diff < 0) { diff += ((int64_t)1 << 32); borrow = 1; }
                else borrow = 0;
                r[i] = (uint32_t)diff;
            }
        }
    }

    for (i = 0; i < 8; i++) {
        out[4*i]   = (uint8_t)(r[i]);
        out[4*i+1] = (uint8_t)(r[i] >> 8);
        out[4*i+2] = (uint8_t)(r[i] >> 16);
        out[4*i+3] = (uint8_t)(r[i] >> 24);
    }
}

/**
 * @brief Compute s = (a*b + c) mod l (RFC 8032 §5.1.6 step 7).
 *
 * a, b, c and the result s are 32-byte little-endian scalars. The product
 * a*b is formed with a schoolbook byte-wise multiply into a 64-byte
 * accumulator (each partial sum a[i]*b[j] is at most 255*255 and at most 32
 * such terms land on any one byte position, so the per-position accumulator
 * never exceeds ~2^21 and fits comfortably in uint32_t even before carry
 * propagation). c is added (zero-extended to 64 bytes) with carry, and the
 * 512-bit result is reduced mod l via the existing `sc_reduce`.
 */
static void sc_muladd(uint8_t s[32], const uint8_t a[32], const uint8_t b[32],
                       const uint8_t c[32]) {
    uint32_t acc[64] = {0};
    uint8_t prod[64];
    int i, j;
    uint32_t carry;

    for (i = 0; i < 32; i++) {
        for (j = 0; j < 32; j++) {
            acc[i + j] += (uint32_t)a[i] * (uint32_t)b[j];
        }
    }

    carry = 0;
    for (i = 0; i < 64; i++) {
        uint32_t v = acc[i] + carry + (i < 32 ? c[i] : 0);
        prod[i] = (uint8_t)v;
        carry = v >> 8;
    }

    sc_reduce(s, prod);
}

/**
 * @brief Derive the 32-byte clamped scalar `a` and 32-byte `prefix` from a
 * 32-byte Ed25519 seed, per RFC 8032 §5.1.5 steps 1-2.
 */
static void ed25519_expand_seed(const uint8_t seed[32], uint8_t a[32], uint8_t prefix[32]) {
    uint8_t h[64];
    mbedtls_sha512_context sha;

    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    mbedtls_sha512_update(&sha, seed, 32);
    mbedtls_sha512_finish(&sha, h);
    mbedtls_sha512_free(&sha);

    memcpy(a, h, 32);
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;

    memcpy(prefix, h + 32, 32);
}

/* ── Public API ──────────────────────────────────────────────────────────── */

/**
 * Derive the 32-byte Ed25519 public key from a 32-byte private seed
 * (RFC 8032 §5.1.5).
 */
void ed25519_pubkey_from_seed(const uint8_t seed[32], uint8_t pub_out[32]) {
    uint8_t a[32], prefix[32];
    ge_p3 A;

    ed25519_expand_seed(seed, a, prefix);
    ge_scalarmult_base(&A, a);
    ge_p3_to_bytes(pub_out, &A);
}

/**
 * Sign a message with Ed25519 PureEdDSA (RFC 8032 §5.1.6).
 */
void ed25519_sign(const uint8_t seed[32], const uint8_t *msg, size_t msg_len,
                   uint8_t sig_out[64]) {
    uint8_t a[32], prefix[32], pub[32];
    uint8_t h[64], r[32], k[32];
    mbedtls_sha512_context sha;
    ge_p3 R_point;

    ed25519_expand_seed(seed, a, prefix);
    ge_scalarmult_base(&R_point, a);
    ge_p3_to_bytes(pub, &R_point);

    /* r = SHA-512(prefix || msg) mod l */
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    mbedtls_sha512_update(&sha, prefix, 32);
    mbedtls_sha512_update(&sha, msg, msg_len);
    mbedtls_sha512_finish(&sha, h);
    mbedtls_sha512_free(&sha);
    sc_reduce(r, h);

    /* R = [r]B */
    ge_scalarmult_base(&R_point, r);
    ge_p3_to_bytes(sig_out, &R_point);

    /* k = SHA-512(R || A || msg) mod l */
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0);
    mbedtls_sha512_update(&sha, sig_out, 32);
    mbedtls_sha512_update(&sha, pub, 32);
    mbedtls_sha512_update(&sha, msg, msg_len);
    mbedtls_sha512_finish(&sha, h);
    mbedtls_sha512_free(&sha);
    sc_reduce(k, h);

    /* S = (k*a + r) mod l */
    sc_muladd(sig_out + 32, k, a, r);
}

int ed25519_verify(const uint8_t pk[32],
                   const uint8_t sig[64],
                   const uint8_t *msg, size_t msg_len) {
    /* RFC 8032 §5.1.7 */
    /* Step 1: Check sig[32..63] (s) < l */
    if ((sig[63] & 0xe0) != 0) { return -1; }
    if (!sc_check(sig + 32)) { return -1; }

    /* Step 2: Decode public key A */
    ge_p3 A;
    if (ge_frombytes(&A, pk) != 0) { return -1; }
    /* Negate A for the verification equation [s]B - [k]A = R */
    fe_neg(A.X, A.X);
    fe_neg(A.T, A.T);

    /* Step 3: Compute k = SHA-512(R || pk || msg) mod l */
    uint8_t h[64];
    mbedtls_sha512_context sha;
    mbedtls_sha512_init(&sha);
    mbedtls_sha512_starts(&sha, 0); /* 0 = SHA-512 (not SHA-384) */
    mbedtls_sha512_update(&sha, sig, 32);   /* R */
    mbedtls_sha512_update(&sha, pk, 32);    /* A (public key) */
    mbedtls_sha512_update(&sha, msg, msg_len);
    mbedtls_sha512_finish(&sha, h);
    mbedtls_sha512_free(&sha);

    uint8_t k[32];
    sc_reduce(k, h);

    /* Step 4: Compute check_R = [s]B + [k](-A) = [s]B - [k]A */
    ge_p3 check;
    ge_double_scalarmult_vartime(&check, sig + 32, &A, k);

    /* Step 5: Encode check_R and compare with sig[0..31] */
    uint8_t check_bytes[32];
    ge_p3_to_bytes(check_bytes, &check);

    /* Constant-time comparison */
    uint8_t diff = 0;
    int i;
    for (i = 0; i < 32; i++) { diff |= check_bytes[i] ^ sig[i]; }
    return (diff == 0) ? 0 : -1;
}
