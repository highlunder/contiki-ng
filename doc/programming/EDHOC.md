# EDHOC - Ephemeral Diffie-Hellman Over COSE

## Overview

EDHOC (Ephemeral Diffie-Hellman Over COSE) is a lightweight authenticated key agreement protocol specified in [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html). The protocol was designed specifically for constrained IoT devices, providing mutual authentication, perfect forward secrecy, and identity protection while minimizing message sizes and computational overhead.

The Contiki-NG implementation enables secure key agreement between IoT devices using COSE for cryptography, CBOR for encoding, and CoAP for transport. The implementation has been verified against the test vectors provided in [RFC 9529](https://www.rfc-editor.org/rfc/rfc9529.html).

### Key Features

The implementation supports cipher suites 2 and 3, which use AES-CCM for authenticated encryption with the P-256 elliptic curve and ES256 signatures. All four EDHOC authentication methods (0, 1, 2, and 3) are supported, allowing for flexible deployment scenarios ranging from signature-based authentication to static Diffie-Hellman keys.

Two credential types are available: KID (Key Identifier) mode for scenarios where keys are pre-provisioned, and CCS (CWT Claims Set) mode where credentials are embedded directly in the protocol messages. On platforms with hardware cryptographic accelerators, such as the CC2538, the implementation can leverage hardware ECC operations for improved performance and lower power consumption.

The implementation integrates seamlessly with CoAP, using the standard `.well-known/edhoc` URI path. For messages larger than typical MTU sizes, CoAP Block-Wise Transfer (RFC 7959) provides automatic fragmentation support.

## Configuration

EDHOC is configured through compile-time macros defined in your application's `project-conf.h` file. This approach minimizes memory footprint by allowing unused features to be excluded at compile time.

### Essential Configuration Parameters

Each EDHOC endpoint must be configured with a role (initiator or responder), an authentication key identifier, a connection identifier, an authentication method, and an ECC implementation preference.

The role determines whether the device acts as the EDHOC initiator (typically the CoAP client) or responder (typically the CoAP server). Use `EDHOC_CONF_ROLE` with either `EDHOC_INITIATOR` or `EDHOC_RESPONDER`.

Authentication keys are identified using either `EDHOC_AUTH_KID` for numeric identifiers or `EDHOC_AUTH_SUBJECT_NAME` for string-based subject names. This identifier allows peers to locate the correct public key for authentication.

Connection identifiers (CIDs) uniquely identify each EDHOC session. The `EDHOC_CONF_CID` macro sets this value. Connection identifiers can be single-byte values encoded as CBOR unsigned integers (0x00-0x17) or negative integers (0x20-0x37), or they can be multi-byte values with proper CBOR encoding.

The authentication method, selected via `EDHOC_CONF_METHOD`, determines the authentication approach: METHOD0 uses signatures for both parties, METHOD1 uses signature for initiator and static DH for responder, METHOD2 uses static DH for initiator and signature for responder, and METHOD3 uses static DH for both parties.

The ECC library selection (`EDHOC_CONF_ECC`) determines whether to use the portable micro-ECC software implementation (`EDHOC_UECC_ECC`) or hardware acceleration (`EDHOC_CC2538_ECC`) on supported platforms.

### Optional Configuration

Additional parameters control credential exchange mode (`EDHOC_CONF_CRED_TYPE`), retry behavior (`EDHOC_CONF_ATTEMPTS`), timeout values (`EDHOC_CONF_TIMEOUT`), and the server endpoint for client configurations (`EDHOC_CONF_SERVER_EP`).

Buffer sizes can be adjusted through macros like `EDHOC_MAX_PAYLOAD_LEN`, `EDHOC_MAX_CRED_LEN`, and `EDHOC_MAX_ID_CRED_LEN`, though the defaults are suitable for most deployments.

## Client API (Initiator)

The EDHOC client API provides a process-based interface for devices acting as initiators. The typical workflow involves initializing storage, loading authentication keys, starting the EDHOC protocol, waiting for completion, and exporting the resulting key material.

The main entry point is `edhoc_client_run()`, which spawns a Contiki process that manages the entire EDHOC handshake. This includes generating ephemeral keys, sending message_1 to the responder, receiving and processing message_2, sending message_3, and handling any necessary retries.

Applications monitor the handshake status using `edhoc_client_callback()`, which returns 1 for successful completion, -1 when maximum retry attempts are exceeded, or 0 while the protocol is still in progress. After successful completion, applications export the agreed-upon key material and then call `edhoc_client_close()` to free allocated resources.

The client automatically handles protocol state management, retry logic, and message validation. CoAP Block-Wise Transfer is used transparently when messages exceed size thresholds.

## Server API (Responder)

The server API offers both blocking and asynchronous interfaces. The blocking API is simpler but ties up the CoAP handler during cryptographic operations, which can be problematic on constrained devices. The asynchronous API is recommended for production deployments.

### Blocking Interface

The blocking interface centers around `edhoc_server_process()`, which processes incoming EDHOC messages synchronously. While this approach is straightforward, it blocks the CoAP handler during potentially lengthy cryptographic operations, preventing the server from handling other requests. This API is primarily useful for testing or single-client scenarios.

### Asynchronous Interface

The asynchronous API uses `edhoc_server_process_async()` with callback functions to decouple EDHOC processing from the CoAP handler. When an EDHOC message arrives, the handler queues the message for processing and returns immediately, allowing the CoAP stack to continue serving other requests. When processing completes, the provided callback function is invoked with the result.

This design integrates naturally with CoAP separate responses as specified in RFC 7252. The server acknowledges the incoming request immediately with an empty ACK, processes the EDHOC message asynchronously, and sends the actual response as a separate confirmable message when processing completes.

The callback-based design allows applications to manage multiple concurrent EDHOC sessions without blocking. It also provides a clean separation between protocol processing and application logic, making it easier to integrate EDHOC into existing CoAP server applications.

## Key Storage and Credentials

Before running EDHOC, authentication keys must be provisioned into the key storage system. The key storage API provides functions to initialize storage (`edhoc_key_storage_init()`), add keys (`edhoc_key_storage_add()`), and retrieve keys by identifier (`edhoc_key_storage_get()`).

Keys are represented using the COSE key format, which includes the key type, curve parameters, public key coordinates, and optionally the private key. For elliptic curve keys on the P-256 curve, the structure contains the x and y coordinates of the public key point, along with the private key d value for the device's own authentication key.

### Credential Exchange Modes

EDHOC supports two credential exchange modes. In KID mode (`EDHOC_CRED_KID`), peers exchange only key identifiers in the protocol messages. Each device must have the peer's public key pre-provisioned in its key storage, referenced by the key identifier. This mode minimizes message sizes but requires out-of-band key distribution.

In CCS mode (`EDHOC_CRED_INCLUDE`), credentials are embedded directly in the EDHOC messages using the CWT Claims Set format. This allows peers to authenticate without prior key provisioning, though it increases message sizes. The receiving device can validate and optionally store the credential during protocol execution.

The choice between modes depends on deployment constraints. KID mode is preferred when keys can be provisioned during device manufacturing or commissioning, while CCS mode offers more flexibility for dynamic environments where devices may not know each other in advance.

## Key Export

After successful EDHOC completion, the established shared secret can be used to derive application-specific key material. The key export interface implements the EDHOC-Exporter mechanism from RFC 9528, which uses HKDF-Expand to derive keys with cryptographic separation between different applications.

The `edhoc_exporter()` function takes a label (to identify the application), optional context data (for additional binding), and an output buffer. Different labels produce independent key streams, allowing multiple applications to derive keys from the same EDHOC session without compromising security.

Applications typically export keys immediately after a successful handshake, then clean up the EDHOC context to free memory. The exported keys can be used for application-layer encryption, message authentication, or as input to further key derivation functions.

## Examples and Testing

Complete working examples are provided in `examples/edhoc/edhoc-client/` and `examples/edhoc/edhoc-server/`. These examples demonstrate full client and server implementations, including key provisioning, protocol execution, and key export. The examples can be built for various platforms including native, CC2538DK, and other supported targets.

The implementation includes comprehensive test suites. RFC 9529 test vectors are validated in `tests/08-native-runs/`, ensuring compliance with the specification. Integration tests in `tests/21-security-protocols/` cover all authentication methods, both credential modes, block-wise transfer scenarios, and error handling paths.

## Performance Considerations

Performance characteristics vary significantly between hardware-accelerated and software-only configurations. The CC2538 platform with hardware ECC acceleration (`EDHOC_CONF_ECC EDHOC_CC2538_ECC`) provides faster operations and lower power consumption. The hardware accelerator handles ECDH and ECDSA operations efficiently without requiring CPU clock increases or watchdog modifications.

When using the micro-ECC software implementation (`EDHOC_CONF_ECC EDHOC_UECC_ECC`) on platforms like the Zolertia RE-Mote, elliptic curve operations may require several hundred milliseconds. On slower platforms, you may need to increase the CPU clock frequency to 32 MHz or temporarily disable the watchdog timer to prevent resets during cryptographic operations. The necessary configuration macros are `SYS_CTRL_CONF_SYS_DIV` and `WATCHDOG_CONF_ENABLE`.

The choice of cipher suite and authentication method also affects performance. Static Diffie-Hellman authentication (METHOD3) generally requires less computation than signature-based methods, though the difference depends on the specific ECC implementation.

## Dependencies

The EDHOC implementation builds on several cryptographic and encoding libraries. CBOR encoding and decoding is handled by Contiki-NG's integrated CBOR implementation, which correctly handles both unsigned and signed integer encodings as required by the EDHOC specification.

COSE cryptographic operations are provided by the module in `os/net/security/cose/`, which implements COSE_Encrypt0 for authenticated encryption and COSE_Sign1 for signature operations. This module also defines the COSE_key format used for key storage.

Elliptic curve cryptography is provided by either micro-ECC or platform-specific hardware drivers. The micro-ECC library, included as a git submodule in `os/net/security/micro-ecc/`, is a portable software implementation supporting the P-256 curve. The CC2538 hardware driver in `arch/cpu/cc2538/dev/ecc-driver.*` interfaces with the PKA hardware accelerator for improved performance on that platform.

The client and server examples additionally depend on the CoAP engine in `os/net/app-layer/coap/`, which provides the transport layer for EDHOC messages.

## Troubleshooting

Common issues typically relate to platform-specific constraints. Watchdog timeouts during EDHOC handshakes indicate that cryptographic operations are taking too long. Enable hardware acceleration if available, or adjust the CPU clock and watchdog settings as described in the performance section.

Algorithm-related errors, such as "Unknown COSE signing algorithm," indicate cipher suite mismatches between peers. Ensure both parties are configured to use cipher suite 2 or 3, as these are the only suites currently supported.

Connection identifier problems usually stem from incorrect CBOR encoding. Single-byte CIDs in the ranges 0x00-0x17 or 0x20-0x37 are encoded as CBOR integers, while longer identifiers require byte string encoding. The implementation handles standard encodings automatically, but custom CID schemes should follow CBOR conventions.

For detailed protocol debugging, enable EDHOC debug logging by defining `LOG_CONF_LEVEL_EDHOC` to `LOG_LEVEL_DBG`. This provides detailed output about protocol state transitions, message content, and error conditions.

## References

- [RFC 9528](https://www.rfc-editor.org/rfc/rfc9528.html) - EDHOC Specification
- [RFC 9529](https://www.rfc-editor.org/rfc/rfc9529.html) - EDHOC Test Vectors
- [CoAP Documentation](CoAP.md)
- [Communication Security](Communication-Security.md)
