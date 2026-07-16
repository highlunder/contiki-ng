/**
 * @file c509-x509-wrap.h
 * @brief cbor-free wrapper around c509_parse_cert() + x509_encode_full_cert().
 *
 * The c509 decoder header (cbor.h) defines an anonymous-enum cbor_major_type_t
 * that collides with os/lib/cbor.h's named enum of the same name. Any EDHOC
 * translation unit already pulls in os/lib/cbor.h, so it cannot also include the
 * c509 cbor types. This wrapper keeps all c509/cbor headers inside its own .c and
 * exposes only stdint/stddef types, letting an EDHOC app reconstruct X.509 DER
 * from C509 without the header clash.
 */
#ifndef C509_X509_WRAP_H_
#define C509_X509_WRAP_H_

#include <stdint.h>
#include <stddef.h>

/**
 * @brief Parse a C509 certificate and reconstruct its full X.509 DER.
 *
 * Safe when @p out aliases @p c509 (the input is copied internally before
 * encoding), so it can be used for in-place C509 -> DER conversion.
 *
 * @param c509      C509 certificate bytes (CBOR array or legacy sequence form).
 * @param c509_len  length of @p c509.
 * @param out       output buffer for the reconstructed X.509 DER.
 * @param out_size  capacity of @p out.
 * @param out_len   [out] number of DER bytes written on success.
 * @return 0 on success, <0 on error.
 */
int c509_to_x509_der(const uint8_t *c509, size_t c509_len,
                     uint8_t *out, size_t out_size, size_t *out_len);

/**
 * @brief Convert a C509 Type-3 CSR to a PKCS#10 DER CertificationRequest.
 *
 * Thin cbor-free wrapper around x509_encode_csr(); keeps the c509/cbor headers
 * out of the caller's translation unit (same rationale as c509_to_x509_der).
 * Safe when @p out aliases @p c509 (input copied internally first).
 *
 * @param c509      C509 Type-3 CSR bytes (flat sequence or CBOR array).
 * @param c509_len  length of @p c509.
 * @param out       output buffer for the PKCS#10 DER CertificationRequest.
 * @param out_size  capacity of @p out.
 * @param out_len   [out] number of DER bytes written on success.
 * @return 0 on success, <0 on error.
 */
int c509_csr_to_pkcs10_der(const uint8_t *c509, size_t c509_len,
                           uint8_t *out, size_t out_size, size_t *out_len);

#endif /* C509_X509_WRAP_H_ */
