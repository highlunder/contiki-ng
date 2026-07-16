/* Host test for the on-device C509 OCSP response codec (c509-ocsp) and the
 * revocation-object TBS/signature locator (c509-rev-verify's locate path),
 * validated against the c509rev reference KAT vectors.
 *
 * Build + run (host):
 *   gcc -Wall -Wextra -I../../os/services/c509 -o c509-ocsp-hosttest \
 *       c509-ocsp-hosttest.c
 *   ./c509-ocsp-hosttest        # expect: ALL TESTS PASSED
 */
#include <stdio.h>
#include <string.h>

#include "c509-ocsp.h"
#include "c509-rev-verify.h"

/* Compile the modules under test (+ shared walker) directly. */
#include "c509-cbor-lite.c"
#include "c509-ocsp.c"
#include "c509-ocsp-req.h"
#include "c509-ocsp-req.c"

/* Stub the Ed25519 primitive so c509-rev-verify.c links without mbedTLS; it
 * records the (msg, sig) it is handed so we can byte-check the TBS locator.
 * The real Ed25519 KAT runs in the Contiki build (mbedTLS available). */
static const uint8_t *g_msg;
static size_t g_msg_len;
static const uint8_t *g_sig;
int
ed25519_verify(const uint8_t pk[32], const uint8_t sig[64],
               const uint8_t *msg, size_t msg_len)
{
  (void)pk;
  g_sig = sig;
  g_msg = msg;
  g_msg_len = msg_len;
  return 0;
}
/* Stub the ECDSA signer that c509-ocsp-req.c's signed-request builder calls, so
 * the host test links crypto-free and can byte-check the request's TBS layout
 * (the signature bytes themselves are exercised by the real 07-c509 round-trip).
 * Writes a fixed marker signature. */
int
x509_csr_sign_msg(const uint8_t *msg, size_t msg_len,
                  const uint8_t *priv_key, size_t priv_key_len, uint8_t *sig_out)
{
  (void)msg; (void)msg_len; (void)priv_key; (void)priv_key_len;
  memset(sig_out, 0xAB, 64);
  return 0;
}
#include "c509-rev-verify.c"

static size_t
unhex(const char *h, uint8_t *out)
{
  size_t n = 0;
  for(; h[0] && h[1]; h += 2) {
    unsigned v;
    sscanf(h, "%2x", &v);
    out[n++] = (uint8_t)v;
  }
  return n;
}

static int fails = 0;
static void
checkl(const char *name, long got, long want)
{
  if(got != want) {
    printf("FAIL %s: got %ld want %ld\n", name, got, want);
    fails++;
  } else {
    printf("ok   %s = %ld\n", name, got);
  }
}

/* c509rev ocsp_resp.rs KATs. */
static const char *SIMPLE_RESP =
  "8e020c005011111111111111111111111111111111480600867838e3"
  "311a48a01c73a5f3b063345410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d001a67c4f10039707f1962708"
  "0f65840e3419955aeb3d74ad5bc7d32264e8976c3ab6f68643c6bf66cc2f9352ff3e861a0bd1506c78b09d3fa"
  "e869d1fd3c87ef461cf6d2096ea0ac11fcff5ebc0fa70c";

static const char *BASIC_RESP =
  "8a010c005011111111111111111111111111111111480600867838e3311a"
  "1a67c4f100808648a01c73a5f3b06334808f5410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d0039707f1962"
  "70805475d8bc4fbafc6694467641e748dfd53a8b9d176d0139707f1962708054d1ac135d7da29bdcf4dca0d528"
  "1a51605b678400821a67c32f000439707f19627080482222222222222222808554d3a0c1e3db92e8f6810537d4"
  "5cfaecf6ce417e3b0239707f19627080f65840e4869c57a66bab501acaeb7e5024105253d72f45d349ae21fb94"
  "1abe4435f8a6c9d1ca5d2784ab30cf177ff075b5502aeaee09c1146cf490663eaed9243a760d";

/* c509rev crl.rs "no revoked" KAT (for the TBS/sig locator). */
static const char *CRL_NO_REVOKED =
  "8b000c6f746573742063726c6f6373702d6361542f45e78d2c"
  "aedf368cdf53c39005d492450e1056011a6775d7001a00093a80f680f6584013834f4e38aa9f0dc5b8d21c86"
  "50c776a6d961c31c894c36a71a6433f5ed7d30e67f787f13c7e4c349b2848a181fdbbce361a14c220021c4a2"
  "67367ad5f1d90d";

int
main(void)
{
  uint8_t buf[512];
  c509_ocsp_result_t r;

  /* --- Simple response (type 2), single Good cert --- */
  size_t n = unhex(SIMPLE_RESP, buf);
  checkl("simple type", c509_ocsp_resp_type(buf, n), 2);
  /* issuerCertHash@31 (8B), serialNumberHash@40 (20B) */
  checkl("simple lookup(match)",
         c509_ocsp_lookup(buf, n, buf + 31, 8, buf + 40, 20, &r), 0);
  checkl("simple status", r.status, C509_OCSP_GOOD);
  /* wrong serial -> no match */
  uint8_t bogus[20]; memset(bogus, 0xAB, 20);
  checkl("simple lookup(miss)",
         c509_ocsp_lookup(buf, n, buf + 31, 8, bogus, 20, &r), 1);

  /* --- Basic response (type 1), 2 issuers, 4 singles --- */
  n = unhex(BASIC_RESP, buf);
  checkl("basic type", c509_ocsp_resp_type(buf, n), 1);
  /* issuer0@38 (8B); serials@49,78,107 (20B) */
  checkl("basic lookup g",
         c509_ocsp_lookup(buf, n, buf + 38, 8, buf + 49, 20, &r), 0);
  checkl("basic status good", r.status, C509_OCSP_GOOD);
  checkl("basic lookup ni",
         c509_ocsp_lookup(buf, n, buf + 38, 8, buf + 78, 20, &r), 0);
  checkl("basic status notissued", r.status, C509_OCSP_NOT_ISSUED);
  checkl("basic lookup rev",
         c509_ocsp_lookup(buf, n, buf + 38, 8, buf + 107, 20, &r), 0);
  checkl("basic status revoked", r.status, C509_OCSP_REVOKED);
  checkl("basic revocation_time", (long)r.revocation_time, 1740844800L);
  checkl("basic revocation_reason", (long)r.revocation_reason, 4);
  /* issuer1@142 (8B); serial@153 (20B) -> Unknown */
  checkl("basic lookup unk",
         c509_ocsp_lookup(buf, n, buf + 142, 8, buf + 153, 20, &r), 0);
  checkl("basic status unknown", r.status, C509_OCSP_UNKNOWN);
  /* issuer0 + issuer1's serial -> no match (serial belongs to the other issuer) */
  checkl("basic cross-issuer miss",
         c509_ocsp_lookup(buf, n, buf + 38, 8, buf + 153, 20, &r), 1);

  /* --- Error response --- */
  uint8_t err[] = { 0x82, 0x00, 0x06 };
  int64_t es = 0;
  checkl("error type", c509_ocsp_resp_type(err, sizeof(err)), 0);
  checkl("error status ret", c509_ocsp_error_status(err, sizeof(err), &es), 0);
  checkl("error status val", (long)es, 6);

  /* --- TBS/signature locator (c509-rev-verify) against the CRL KAT --- */
  n = unhex(CRL_NO_REVOKED, buf);
  const uint8_t *tbs, *sig;
  size_t tbs_len, sig_len;
  checkl("locate ret", c509_rev_locate_tbs(buf, n, &tbs, &tbs_len, &sig, &sig_len), 0);
  checkl("tbs offset", (long)(tbs - buf), 1);          /* just past the 0x8b array head */
  checkl("tbs len", (long)tbs_len, (long)n - 67);      /* strip head(1)+58 40(2)+sig(64) */
  checkl("sig offset", (long)(sig - buf), (long)n - 64);
  checkl("sig len", (long)sig_len, 64);
  /* verify-path handoff: c509_rev_verify_ed25519 must pass exactly that TBS+sig */
  uint8_t pk[32] = { 0 };
  checkl("verify ret(stub)", c509_rev_verify_ed25519(buf, n, pk), 0);
  checkl("verify msg==tbs", (long)(g_msg == tbs && g_msg_len == tbs_len), 1);
  checkl("verify sig==sig", (long)(g_sig == sig), 1);

  /* --- OCSP request builders (build must reproduce the draft KATs) --- */
  /* Simple request: nonce@4 (16B), issuerCertHash@21 (8B), serial@30 (20B). */
  static const char *SIMPLE_REQ =
    "860200501111111111111111111111111111111148a01c73a5f3b063"
    "345410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d80";
  uint8_t kat[256], built[256];
  size_t kn = unhex(SIMPLE_REQ, kat), bn = 0;
  int rc = c509_ocsp_build_simple_request(built, sizeof(built), &bn,
                                          0 /*SHA-256*/,
                                          kat + 4, 16, kat + 21, 8, kat + 30, 20);
  checkl("simple req build ret", rc, 0);
  checkl("simple req len", (long)bn, (long)kn);
  checkl("simple req bytes", (long)(bn == kn && memcmp(built, kat, kn) == 0), 1);

  /* Unsigned request: nonce@4; issuer0@23, serials@34/56/78; issuer1@100, serial@111. */
  static const char *UNSIGNED_REQ =
    "8500005011111111111111111111111111111111808648a01c73a5f3"
    "b0633480865410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d805475d8bc4fbafc6694467641e748dfd53a8"
    "b9d176d8054d1ac135d7da29bdcf4dca0d5281a51605b67840080482222222222222222808254d3a0c1e3db92"
    "e8f6810537d45cfaecf6ce417e3b80";
  kn = unhex(UNSIGNED_REQ, kat);
  c509_ocsp_single_t g0s[3] = {
    { kat + 34, 20 }, { kat + 56, 20 }, { kat + 78, 20 }
  };
  c509_ocsp_single_t g1s[1] = { { kat + 111, 20 } };
  c509_ocsp_group_t groups[2] = {
    { kat + 23, 8, g0s, 3 },
    { kat + 100, 8, g1s, 1 }
  };
  bn = 0;
  rc = c509_ocsp_build_unsigned_request(built, sizeof(built), &bn, 0,
                                        kat + 4, 16, groups, 2);
  checkl("unsigned req build ret", rc, 0);
  checkl("unsigned req len", (long)bn, (long)kn);
  checkl("unsigned req bytes", (long)(bn == kn && memcmp(built, kat, kn) == 0), 1);

  /* signatureAlgorithm reader on the CRL (element 1 = 0x0c = SIG_ED25519). */
  n = unhex(CRL_NO_REVOKED, buf);
  int64_t alg = -999;
  checkl("sig_alg ret", c509_rev_sig_alg(buf, n, &alg), 0);
  checkl("sig_alg value", (long)alg, 12);

  /* Signed OCSP request (type 1): build the TBS with the draft's SIGNED_REQ_NO_CERT
   * parameters (sigAlg=SIG_ED25519=12) and confirm the TBS bytes match the draft
   * example. The stub signer fills sigValue; the real signature is exercised in
   * 07-c509. TBS = out[1 .. out_len-66] (strip array head + 58 40 + 64-byte sig). */
  static const char *SIGNED_REQ_NO_CERT =
    "89010c0050111111111111111111111111111111114844f052"
    "8b56f35ad9808648a01c73a5f3b0633480865410652787fa0527bc2449a1bfc5ab31aa5a6f0d8d805475d8bc4"
    "fbafc6694467641e748dfd53a8b9d176d8054d1ac135d7da29bdcf4dca0d5281a51605b67840080482222222222"
    "222222808254d3a0c1e3db92e8f6810537d45cfaecf6ce417e3b80f658407da70be70d8c88f5150218b2f60a21"
    "320d26faf8dc198f16654d54cb617a1c3c3f420b3f2fbf74c9b107d81d1815c2ce09b22eaf491313003c49d43a"
    "ab8d970b";
  kn = unhex(SIGNED_REQ_NO_CERT, kat);
  /* offsets: nonce@5, requestorCertHash@22, issuer0@33, serials@44/66/88,
   * issuer1@110, serial@121. */
  c509_ocsp_single_t sg0[3] = { { kat + 44, 20 }, { kat + 66, 20 }, { kat + 88, 20 } };
  c509_ocsp_single_t sg1[1] = { { kat + 121, 20 } };
  c509_ocsp_group_t sgroups[2] = { { kat + 33, 8, sg0, 3 }, { kat + 110, 8, sg1, 1 } };
  uint8_t privdummy[32] = { 0 };
  bn = 0;
  rc = c509_ocsp_build_signed_request(built, sizeof(built), &bn,
                                      12 /*SIG_ED25519*/, 0 /*SHA-256*/,
                                      kat + 5, 16, kat + 22, 8, sgroups, 2,
                                      NULL, 0, privdummy, 32);
  checkl("signed req build ret", rc, 0);
  checkl("signed req len", (long)bn, (long)kn);
  checkl("signed req TBS matches draft",
         (long)(bn == kn && memcmp(built + 1, kat + 1, (size_t)kn - 66) == 0), 1);
  checkl("signed req sigValue header", (long)(built[bn - 66] == 0x58 && built[bn - 65] == 0x40), 1);

  printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
  return fails ? 1 : 0;
}
