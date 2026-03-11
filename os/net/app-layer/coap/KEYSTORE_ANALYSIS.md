# CoAP Keystore API Analysis

## Current State
The CoAP Keystore API allows the DTLS stack to retrieve credentials (PSK or X.509 Certificates) for an endpoint.

### Components
- `coap-keystore.h`: Interface definitions and `coap_set_keystore`.
- `coap-uip.c`: Storage of the active keystore and internal wrapper functions.
- `coap-keystore-simple.c`: A reference implementation using static credentials.

### Identified Weaknesses
1. **Encapsulation**: The active keystore is stored as a static pointer in `coap-uip.c`. There is no official "getter" (`coap_get_keystore`), making it difficult for other modules (like C509) to interact with it.
2. **Type Consistency**: 
    - `coap_keystore_cert_entry_t` members are `const uint8_t *` for data but `uint16_t` for length.
    - Some implementations (`coap-keystore-simple.c`) cast away `const` unnecessarily.
3. **Sparse Documentation**: The headers lack detailed Doxygen comments explaining return values and expected behavior.
4. **Mixed Responsibilities**: `coap-uip.c` handles both CoAP networking and keystore storage.
5. **Ambiguous Error Codes**: Callbacks return `int`, but there's no defined set of error constants.

## Proposed Improvements
1. **Formalize Getter/Setter**: Move `coap_get_keystore` to the public API in `coap-keystore.h`.
2. **Add High-Level Retrieval API**:
    - Add `coap_keystore_get_psk_info()`
    - Add `coap_keystore_get_cert_info()`
    - Add `coap_keystore_get_c509_info()`
    These functions will handle the "NULL keystore" and "NULL callback" checks centrally.
3. **Documentation**: Add full Doxygen comments to all structures and functions.
4. **Consistency**: Use `const void *` or `const uint8_t *` consistently for read-only buffers.

## Plan
1. Update `coap-keystore.h` with improved documentation and the new retrieval API.
2. Update `coap-uip.c` to implement the retrieval API.
3. Update `coap-keystore-simple.c` to use the improved types and fix `const` casting.
4. Verify with a test application.
