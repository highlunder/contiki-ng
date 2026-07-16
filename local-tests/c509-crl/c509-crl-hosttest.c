#include <stdio.h>
#include <string.h>
#include "c509-crl.h"

/* Compile the module under test (+ its shared CBOR walker) directly. */
#include "c509-cbor-lite.c"
#include "c509-crl.c"

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

static const char *CRL_NO_REVOKED =
  "8b000c6f746573742063726c6f6373702d6361542f45e78d2c"
  "aedf368cdf53c39005d492450e1056011a6775d7001a00093a80f680f6584013834f4e38aa9f0dc5b8d21c86"
  "50c776a6d961c31c894c36a71a6433f5ed7d30e67f787f13c7e4c349b2848a181fdbbce361a14c220021c4a2"
  "67367ad5f1d90d";

static const char *CRL_REVOKED =
  "8b000c6f746573742063726c6f6373702d6361542f45e78d2caedf36"
  "8cdf53c39005d492450e1056021a677c71721a00093a80f68085f6840302031a677488728218571a67748580"
  "5824112206978006123400000001334403f480065566015180065678054600009abc02a30000f6584070bb7a"
  "38065fbcabfe615170f05a9a9fe83dc892d5f735812b2a053af4b300eb466babb4f1a387cdce90d8302c680b7"
  "7aa61566423d7c235f7bd31344cf7f405";

static int fails = 0;

static void
check(const char *name, int got, int want)
{
  if(got != want) {
    printf("FAIL %s: got %d want %d\n", name, got, want);
    fails++;
  } else {
    printf("ok   %s = %d\n", name, got);
  }
}

static int
revoked16(c509_crl_t *crl, uint16_t s)
{
  uint8_t b[2] = { (uint8_t)(s >> 8), (uint8_t)s };
  return c509_crl_is_revoked(crl, b, 2);
}

static int
reason16(c509_crl_t *crl, uint16_t s)
{
  uint8_t b[2] = { (uint8_t)(s >> 8), (uint8_t)s };
  return c509_crl_reason(crl, b, 2);
}

int
main(void)
{
  uint8_t buf[512];
  c509_crl_t crl;

  /* --- CRL with 6 revoked certs --- */
  size_t n = unhex(CRL_REVOKED, buf);
  check("parse(revoked)", c509_crl_parse(buf, n, &crl), 0);
  check("group_count", crl.group_count, 1);
  check("serial_len", crl.serial_len, 2);
  check("date_len", crl.date_len, 3);
  check("has_reason", crl.has_reason, 1);
  check("sorted", crl.sorted, 1);
  check("entry_len", crl.entry_len, 6);
  check("n_entries", crl.n_entries, 6);

  check("revoked 0x1122", revoked16(&crl, 0x1122), 1);
  check("revoked 0x1234", revoked16(&crl, 0x1234), 1);
  check("revoked 0x3344", revoked16(&crl, 0x3344), 1);
  check("revoked 0x5566", revoked16(&crl, 0x5566), 1);
  check("revoked 0x5678", revoked16(&crl, 0x5678), 1);
  check("revoked 0x9abc", revoked16(&crl, 0x9abc), 1);

  check("clean  0x0001", revoked16(&crl, 0x0001), 0);
  check("clean  0x2000", revoked16(&crl, 0x2000), 0);
  check("clean  0x4000", revoked16(&crl, 0x4000), 0);
  check("clean  0xffff", revoked16(&crl, 0xffff), 0);

  check("reason 0x1122", reason16(&crl, 0x1122), 6);
  check("reason 0x1234", reason16(&crl, 0x1234), 1);
  check("reason 0x5678", reason16(&crl, 0x5678), 0);
  check("reason 0x9abc", reason16(&crl, 0x9abc), 0);
  check("reason clean 0x2000", reason16(&crl, 0x2000), -1);

  /* --- CRL with no revocations --- */
  n = unhex(CRL_NO_REVOKED, buf);
  check("parse(no-revoked)", c509_crl_parse(buf, n, &crl), 0);
  check("no-revoked n_entries", crl.n_entries, 0);
  check("no-revoked lookup", revoked16(&crl, 0x1234), 0);

  printf("\n%s (%d failures)\n", fails ? "TESTS FAILED" : "ALL TESTS PASSED", fails);
  return fails ? 1 : 0;
}
