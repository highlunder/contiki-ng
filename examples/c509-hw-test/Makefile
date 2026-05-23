CONTIKI_PROJECT = c509-server
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

# Use UART0 instead of Segger RTT so output is captured by Renode UART hooks.
NRF52840_USE_RTT = 0

# Enable DTLS with certificate (C509) support, server role only.
MAKE_WITH_DTLS             = 1
MAKE_COAP_DTLS_WITH_CERT   = 1
MAKE_COAP_DTLS_WITH_SERVER = 1
MAKE_COAP_DTLS_KEYSTORE    = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

# Pull in CoAP, C509 service, and heap allocator.
MODULES += os/net/app-layer/coap
MODULES += os/services/c509
MODULES += os/lib

include $(CONTIKI)/Makefile.include
