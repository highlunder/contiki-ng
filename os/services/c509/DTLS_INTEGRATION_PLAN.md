# DTLS Integration Plan for C509 in Contiki-NG

## Goal
Enable the DTLS stack (Mbed TLS) to use C509 certificates by providing a transparent conversion layer during session setup.

## Phase 0: Baseline DTLS Validation
- [ ] **Baseline PSK Test**: Create a test app using standard CoAP/DTLS PSK mode.
- [ ] **Baseline X.509 Test**: Create a test app using standard CoAP/DTLS X.509 Cert mode.
- **Test Case 0.1**: Successful DTLS session initiation using PSK on `native` target.
- **Test Case 0.2**: Successful DTLS session initiation using X.509 on `native` target.

## Phase 1: Keystore API Analysis and Improvement
- [ ] **Analyze Current Keystore**: Evaluate `coap-keystore.h`, `coap-uip.c`, and `coap-keystore-simple.c`.
- [ ] **Document Opportunities**: Identify weaknesses (e.g., lack of getters, mixed responsibilities, sparse documentation).
- [ ] **Implement Improvements**:
    - Add proper getters/setters.
    - Improve type safety and naming consistency.
    - Add Doxygen-style documentation.
- [ ] **Verify Improvements**: Ensure existing PSK/Cert modes still work.
- **Test Case 0**: Verify that the improved Keystore API is functional and correctly documented.

## Phase 2: API Extensions for C509
- [ ] **mbedtls-support.c**: Update `setup_session` to handle `COAP_DTLS_SEC_MODE_C509`.
- [ ] Implement conversion logic within `setup_session`:
    - Parse C509 (CA and Own Cert).
    - Encode to X.509 DER.
    - Pass DER to `mbedtls_x509_crt_parse`.
- **Test Case 2**: Create a mock session setup that uses C509 certificates and verify that Mbed TLS successfully parses the resulting DER.

## Phase 3: Integration and Validation
- [ ] **tests/08-dtls-c509**: Create a full DTLS handshake test using C509 certificates.
- [ ] Verify both Client and Server roles.
- **Test Case 3**: Successful DTLS handshake between two `native` nodes using C509 certificates.

## Phase 4: Performance & Optimization
- [ ] Measure RAM/Flash impact of the conversion layer.
- [ ] Optimize buffer usage (use scratchpad).
