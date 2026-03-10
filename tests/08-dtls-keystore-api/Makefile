CONTIKI_PROJECT = test-keystore-api
all: $(CONTIKI_PROJECT)

# Pull in the CoAP module
MODULES += os/net/app-layer/coap

# Pull in C509 for the headers needed in mbedtls-support.c
MODULES += os/services/c509

# Enable DTLS and certificates to satisfy mbedtls config checks
MAKE_WITH_DTLS = 1
MAKE_COAP_DTLS_WITH_CERT = 1
WERROR = 0

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
