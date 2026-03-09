# C509 Service for Contiki-NG

This service provides support for CBOR Encoded X.509 Certificates (C509), as defined in the IETF draft `draft-ietf-cose-cbor-encoded-cert`.

## Features
- Low-footprint CBOR decoder tailored for C509.
- Structural parsing of C509 certificates.
- Conversion from C509 to X.509 DER format.
- Integration with MbedTLS for cryptographic operations.

## Usage
To use this service in your Contiki-NG application, add it to your `Makefile`:

```makefile
MODULES += os/services/c509
```

Since C509 often requires cryptographic operations, you should also enable MbedTLS. The recommended way is via the CoAP module with DTLS:

```makefile
MODULES += os/net/app-layer/coap
MAKE_WITH_DTLS = 1
MAKE_COAP_DTLS_WITH_CERT = 1
```

## Testing
A test application is available in `tests/07-c509`. To run it:

```bash
cd tests/07-c509
make TARGET=native
./build/native/test-c509.native
```

## Implementation Details
- **CBOR Decoder**: A zero-copy decoder that minimizes memory usage.
- **X.509 Encoder**: Reconstructs standard DER-encoded X.509 certificates from C509 representation.
- **MbedTLS Integration**: Uses MbedTLS for SHA-256 and ECDSA operations.
