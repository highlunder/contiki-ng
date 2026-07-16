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

  printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
  return fails ? 1 : 0;
}
