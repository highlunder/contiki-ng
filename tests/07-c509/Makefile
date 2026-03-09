CONTIKI_PROJECT = test-c509
all: $(CONTIKI_PROJECT)

# Include the C509 service
MODULES += os/services/c509

# Enabling CoAP with DTLS is the standard way to get MbedTLS integrated correctly in Contiki-NG
MODULES += os/net/app-layer/coap
MAKE_WITH_DTLS = 1
MAKE_COAP_DTLS_WITH_CERT = 1

# MbedTLS config uses heapmem
MODULES += os/lib

# Disable Werror because CoAP module has some unused functions when used this way
WERROR = 0

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
