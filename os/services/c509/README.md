# C509 Integration for Contiki-NG

This service enables CBOR Encoded X.509 (C509) certificate support within the Contiki-NG CoAP/DTLS stack. It provides a transparent conversion layer that allows Mbed TLS to use highly compressed C509 certificates as if they were standard X.509 DER certificates.

## Architecture

The integration consists of:
1.  **C509 Parser/Encoder**: Core logic located in `os/services/c509`.
2.  **DTLS Interceptor**: Modifications in `os/net/app-layer/coap/mbedtls-support/mbedtls-support.c` that catch `COAP_DTLS_SEC_MODE_C509` and perform the conversion before passing credentials to Mbed TLS.
3.  **Keystore API Extension**: Updated `coap_keystore_t` to support C509 specific retrieval callbacks.

## Test Server Setup

A standalone test server is provided in `secure-endpoint-test-server/`. It uses OpenSSL `s_server` to provide a robust DTLS 1.2 endpoint.

### Running the Server
To run the server in a private network namespace (bypassing host-level permission issues):
```bash
./secure-endpoint-test-server/run-server.sh
```

## Test Cases

### 1. C509 Secure Handshake
*   **Objective**: Verify end-to-end DTLS 1.2 handshake using C509 certificates.
*   **Configuration**:
    *   `WITH_DTLS=1`
    *   `COAP_DTLS_CONF_WITH_C509=1`
    *   `COAP_DTLS_CONF_DEFAULT_MODE=COAP_DTLS_SEC_MODE_C509`
*   **Success Criteria**: Client logs "Handshake starting" followed by a successful CoAP response (if using a full CoAP server) or the server receiving the encrypted record (if using OpenSSL).

### 2. Standard X.509 (Regression)
*   **Objective**: Ensure standard PKI still works without regressions.
*   **Configuration**:
    *   `WITH_DTLS=1`
    *   `COAP_DTLS_CONF_WITH_CERT=1`
*   **Success Criteria**: Normal X.509 handshake completes successfully.

### 3. PSK (Regression)
*   **Objective**: Ensure Pre-Shared Key mode remains functional.
*   **Configuration**:
    *   `WITH_DTLS=1`
    *   `COAP_DTLS_CONF_WITH_PSK=1`
*   **Success Criteria**: PSK handshake completes successfully.

## Connectivity Requirements
For `native` target testing, a `tun0` device is required. Use the provided namespace scripts to avoid `sudo` requirements.
