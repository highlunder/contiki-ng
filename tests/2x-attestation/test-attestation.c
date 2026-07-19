/*
 * Copyright (c) 2026, RISE Research Institutes of Sweden AB.
 * SECURITY NOTICE: Test credentials only. Never use in production.
 */

/**
 * \file
 *   P0 known-answer tests for the RA-over-EDHOC attestation codec
 *   (os/services/attestation), validated byte-for-byte against
 *   draft-ietf-lake-ra-06 Appendix A -- the C mirror of the Rust reference
 *   impl's tests/appendix_a.rs.
 *
 *   Builds two ways:
 *     - standalone (gcc): `int main` runs the KATs and returns the fail count.
 *     - Contiki (-DCONTIKI_BUILD): a PROCESS runs the KATs and prints the result.
 *
 * \author Joel Hoglund <joel.hoglund@ri.se>
 */
#include "ra-cose.h"
#include "ra-eat.h"
#include "ra-ead.h"
#include "ra-binder.h"
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if CONTIKI_BUILD
#include "contiki.h"
#endif

/* --- Appendix A vectors (verbatim; whitespace stripped by hexdec). --- */
static const char *COSE_HEX =
  "D28443A10127A05890A30A48A29F62A4C6CDAAE5190100476161616262636319011181"
  "82190102A5004574616749440C00016F446F74426F74206669726D7761726502A2181F68"
  "417474657374657218210103A11181A218187819706172746974696F6E302D6E7266353"
  "2383430646B2E62696E078201582006294F6806B9C685EEA795048579CFD02A0C025BC8"
  "B5ABCA42A19EA0EC23E81A5840D4100901F4C3E51312C3110C6DDC8DCF7F68D8F5D3791"
  "C19133F2F0AC158C1F5EE6EDAFE9D7C3D6EB3D2D197F82E733D375FDDA9FB258B304961"
  "DFC38558950D";
static const char *NONCE_HEX = "A29F62A4C6CDAAE5";
static const char *UEID_HEX = "61616162626363"; /* "aaabbcc" */
static const char *BINDER_M3_HEX =
  "7B4C94F32A0E6DB86D915A444F76525FC32912B2E07DD481A96F627EE98A110C";
static const char *PROPOSED_HEX = "83183C183D190102";          /* [60,61,258] */
static const char *SELECTED_HEX = "8219010248A29F62A4C6CDAAE5"; /* (258,nonce) */
#define COSWID_OFFSET 30

/* --- helpers --- */
static int
hexval(char c)
{
  if(c >= '0' && c <= '9') return c - '0';
  if(c >= 'A' && c <= 'F') return c - 'A' + 10;
  if(c >= 'a' && c <= 'f') return c - 'a' + 10;
  return -1;
}
/* Decode hex (skipping whitespace) into out; returns byte length or -1. */
static int
hexdec(const char *s, uint8_t *out, size_t out_sz)
{
  size_t n = 0;
  int hi = -1;
  for(; *s; s++) {
    if(*s == ' ' || *s == '\n' || *s == '\t' || *s == '\r') continue;
    int v = hexval(*s);
    if(v < 0) return -1;
    if(hi < 0) {
      hi = v;
    } else {
      if(n >= out_sz) return -1;
      out[n++] = (uint8_t)((hi << 4) | v);
      hi = -1;
    }
  }
  return (hi < 0) ? (int)n : -1;
}

static int g_pass, g_fail;
#define CHECK(cond, name) do {                                             \
    if(cond) { g_pass++; printf("  ok   %s\n", (name)); }                  \
    else     { g_fail++; printf("  FAIL %s\n", (name)); }                  \
  } while(0)

static int
run_kats(void)
{
  uint8_t cose[512], nonce[64], ueid[64], binder[64], proposed[64], selected[64];
  uint8_t buf[512];
  size_t out_len;
  int cose_len, nonce_len, ueid_len, binder_len, proposed_len, selected_len;

  g_pass = g_fail = 0;
  printf("RA-over-EDHOC (draft-ietf-lake-ra) P0 KATs vs Appendix A\n");

  cose_len = hexdec(COSE_HEX, cose, sizeof(cose));
  nonce_len = hexdec(NONCE_HEX, nonce, sizeof(nonce));
  ueid_len = hexdec(UEID_HEX, ueid, sizeof(ueid));
  binder_len = hexdec(BINDER_M3_HEX, binder, sizeof(binder));
  proposed_len = hexdec(PROPOSED_HEX, proposed, sizeof(proposed));
  selected_len = hexdec(SELECTED_HEX, selected, sizeof(selected));
  if(cose_len < 0 || nonce_len < 0 || ueid_len < 0 || binder_len < 0 ||
     proposed_len < 0 || selected_len < 0) {
    printf("  FAIL vector hex decode\n");
    return 1;
  }

  /* Parse the Appendix-A COSE_Sign1 into its parts. */
  const uint8_t *protected, *payload, *sig;
  size_t plen, paylen, siglen;
  int parsed = ra_cose_parse_sign1(cose, (size_t)cose_len,
                                   &protected, &plen, &payload, &paylen, &sig, &siglen);
  CHECK(parsed == 0, "parse Appendix-A COSE_Sign1");
  CHECK(parsed == 0 && plen == 3 && protected[0] == 0xA1 && protected[1] == 0x01 &&
        protected[2] == 0x27, "protected header {1:-8} (EdDSA)");
  CHECK(parsed == 0 && paylen == 144, "payload length 144");
  CHECK(parsed == 0 && siglen == 64, "signature length 64");
  if(parsed != 0) {
    printf("PASS %d FAIL %d\n", g_pass, g_fail);
    return g_fail;
  }

  /* KAT: EAT minimal-claim-set encoder reproduces the payload. */
  const uint8_t *coswid = payload + COSWID_OFFSET;
  size_t coswid_len = paylen - COSWID_OFFSET;
  CHECK(ra_eat_minimal_claims(buf, sizeof(buf), &out_len, nonce, nonce_len,
                              ueid, ueid_len, 258, coswid, coswid_len) == 0 &&
        out_len == paylen && memcmp(buf, payload, paylen) == 0,
        "EAT minimal-claim-set encoder == Appendix A payload");

  /* KAT: COSE_Sign1 assembler reproduces the whole object. */
  CHECK(ra_cose_sign1(buf, sizeof(buf), &out_len, protected, plen, payload, paylen,
                      sig, siglen) == 0 &&
        out_len == (size_t)cose_len && memcmp(buf, cose, cose_len) == 0,
        "COSE_Sign1 assembler == Appendix A object");

  /* KAT: Sig_structure consumes the binder + payload with the right framing. */
  int ok_ss = ra_cose_sig_structure(buf, sizeof(buf), &out_len, protected, plen,
                                     binder, binder_len, payload, paylen) == 0;
  ok_ss = ok_ss && buf[0] == 0x84 &&
          memcmp(buf + 1, "\x6a" "Signature1", 11) == 0 &&
          memcmp(buf + 12, "\x43\xA1\x01\x27", 4) == 0 &&
          buf[16] == 0x58 && buf[17] == 0x20 &&
          memcmp(buf + 18, binder, 32) == 0 &&
          buf[50] == 0x58 && buf[51] == 0x90 &&
          memcmp(buf + 52, payload, 144) == 0 &&
          out_len == 52 + 144;
  CHECK(ok_ss, "Sig_structure framing (binder as external_aad + payload)");

  /* KAT: EAD Attestation_proposal encoder. */
  uint64_t cfs[3] = { 60, 61, 258 };
  CHECK(ra_ead_proposed_evidence_types(buf, sizeof(buf), &out_len, cfs, 3) == 0 &&
        out_len == (size_t)proposed_len && memcmp(buf, proposed, proposed_len) == 0,
        "EAD Proposed_EvidenceType [60,61,258]");

  /* KAT: EAD Attestation_request encoder + decoder round-trip. */
  CHECK(ra_ead_selected_evidence_type(buf, sizeof(buf), &out_len, 258, nonce, nonce_len) == 0 &&
        out_len == (size_t)selected_len && memcmp(buf, selected, selected_len) == 0,
        "EAD Selected_EvidenceType (258, nonce)");
  {
    uint64_t cf;
    const uint8_t *rn;
    size_t rnlen;
    CHECK(ra_ead_decode_selected(selected, selected_len, &cf, &rn, &rnlen) == 0 &&
          cf == 258 && rnlen == (size_t)nonce_len && memcmp(rn, nonce, nonce_len) == 0,
          "EAD Selected_EvidenceType decode round-trip");
  }

  /* KAT: EAT decoder recovers the claims. */
  {
    const uint8_t *dn, *du, *dm;
    size_t dnl, dul, dml;
    uint64_t dcf;
    CHECK(ra_eat_decode_minimal(payload, paylen, &dn, &dnl, &du, &dul, &dcf, &dm, &dml) == 0 &&
          dnl == (size_t)nonce_len && memcmp(dn, nonce, nonce_len) == 0 &&
          dul == (size_t)ueid_len && memcmp(du, ueid, ueid_len) == 0 &&
          dcf == 258 && dml == coswid_len && memcmp(dm, coswid, coswid_len) == 0,
          "EAT decode_minimal recovers nonce/ueid/measurement");
  }

  /* Structural self-check: attest_info encodes as [ bstr, "attestation", raw ]. */
  {
    uint8_t idc[4] = { 0xA1, 0x04, 0x41, 0x2B }; /* {4: h'2b'} */
    int ok_ai = ra_binder_attest_info(buf, sizeof(buf), &out_len, binder, 32, idc, 4) == 0;
    ok_ai = ok_ai && buf[0] == 0x83 && buf[1] == 0x58 && buf[2] == 0x20 &&
            memcmp(buf + 3, binder, 32) == 0 &&
            memcmp(buf + 35, "\x6b" "attestation", 12) == 0 &&
            memcmp(buf + 47, idc, 4) == 0 && out_len == 51;
    CHECK(ok_ai, "attest_info = [H_12, \"attestation\", ID_CRED_I] framing");
  }

  printf("RESULT: PASS %d FAIL %d\n", g_pass, g_fail);
  return g_fail;
}

#if CONTIKI_BUILD
PROCESS(test_attestation_process, "RA attestation P0 KATs");
AUTOSTART_PROCESSES(&test_attestation_process);
PROCESS_THREAD(test_attestation_process, ev, data)
{
  PROCESS_BEGIN();
  if(run_kats() == 0) {
    printf("=== ATTESTATION P0 KAT PASSED ===\n");
  } else {
    printf("=== ATTESTATION P0 KAT FAILED ===\n");
  }
  PROCESS_END();
}
#else
int
main(void)
{
  int fails = run_kats();
  printf("%s\n", fails == 0 ? "=== ATTESTATION P0 KAT PASSED ===" : "=== ATTESTATION P0 KAT FAILED ===");
  return fails;
}
#endif
