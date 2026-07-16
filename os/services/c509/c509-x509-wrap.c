/**
 * @file c509-x509-wrap.c
 * @brief Implementation of the cbor-free C509 -> X.509 DER wrapper.
 */

#include "c509-x509-wrap.h"
#include "c509.h"
#include "x509_encode.h"
#include <string.h>

/* Largest C509 certificate we reconstruct on the enrollment path is well under
 * this; the copy decouples the parsed cert (which points into the input) from
 * the output buffer so in-place conversion is safe. */
#define C509_WRAP_TMP_SZ 640

int
c509_to_x509_der(const uint8_t *c509, size_t c509_len,
                 uint8_t *out, size_t out_size, size_t *out_len)
{
  uint8_t tmp[C509_WRAP_TMP_SZ];
  c509_cert_t cert;

  if(c509 == NULL || out == NULL || out_len == NULL) {
    return -1;
  }
  if(c509_len == 0 || c509_len > sizeof(tmp)) {
    return -2;
  }
  memcpy(tmp, c509, c509_len);

  if(c509_parse_cert(&cert, tmp, c509_len) != CBOR_ERR_NONE) {
    return -3;
  }
  *out_len = 0;
  if(x509_encode_full_cert(out, out_size, out_len, &cert) != 0) {
    return -4;
  }
  return 0;
}

int
c509_csr_to_pkcs10_der(const uint8_t *c509, size_t c509_len,
                       uint8_t *out, size_t out_size, size_t *out_len)
{
  uint8_t tmp[C509_WRAP_TMP_SZ];

  if(c509 == NULL || out == NULL || out_len == NULL) {
    return -1;
  }
  if(c509_len == 0 || c509_len > sizeof(tmp)) {
    return -2;
  }
  memcpy(tmp, c509, c509_len);

  *out_len = 0;
  if(x509_encode_csr(out, out_size, out_len, tmp, c509_len) != 0) {
    return -3;
  }
  return 0;
}
