# C509 Integration for Contiki-NG

This service enables CBOR Encoded X.509 (C509) certificate support within the Contiki-NG CoAP/DTLS stack. It provides a transparent conversion layer that allows Mbed TLS to use highly compressed C509 certificates as if they were standard X.509 DER certificates.

## Architecture

The integration consists of:
1.  **C509 Parser/Encoder**: Core logic located in `os/services/c509`. Supports P-256 and Ed25519 (infrastructure).
2.  **DTLS Interceptor**: Modifications in `os/net/app-layer/coap/mbedtls-support/mbedtls-support.c` that catch `COAP_DTLS_SEC_MODE_C509` and perform the conversion before passing credentials to Mbed TLS.
3.  **Keystore API Extension**: Updated `coap_keystore_t` to support C509 specific retrieval callbacks.

## Verified Status (March 2026)

The integration has been fully verified on the `native` target using a routed network topology.

### Key Achievements:
- **P-256 Support**: Full reconstruction of SPKI structures and ECC point decompression.
- **Leak-Free**: Verified stable heap usage across multiple handshake cycles after fixing resource leaks in the disconnect handler.
- **Interoperability**: Successful handshakes between Contiki nodes and standalone Mbed TLS servers.

## Test Environment

A standalone test suite is provided in `secure-endpoint-test-server/`. 

### Automated Tests
To run the full routed loopback test (Client <-> Server):
```bash
./secure-endpoint-test-server/run-contiki-full-test.sh
```

## Test Cases

### 1. C509 Secure Handshake (Type 3 & Type 2)
*   **Objective**: Verify end-to-end DTLS 1.2 handshake using C509 certificates.
*   **Status**: **PASS** (Verified on Native).

### 2. Standard X.509 (Regression)
*   **Objective**: Ensure standard PKI still works without regressions.
*   **Status**: **PASS** (Verified on Native).

### 3. PSK (Regression)
*   **Objective**: Ensure Pre-Shared Key mode remains functional.
*   **Status**: **PASS** (Verified on Native).

## Connectivity Requirements
For `native` target testing, `tun` devices are required. The provided scripts use `unshare -rn` to create private network namespaces, avoiding the need for host-level `sudo` for interface configuration.

## Resource Requirements
- **Heap**: At least 32KB (`HEAPMEM_CONF_ARENA_SIZE`) is recommended for Mbed TLS 3.x operations on the native target.
- **Stack**: Standard Contiki-NG stack sizes are sufficient.
