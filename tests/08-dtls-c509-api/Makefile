CONTIKI_PROJECT = test-c509-api
all: $(CONTIKI_PROJECT)

# Enabling CoAP with DTLS is needed to pull in the headers we modified
MODULES += os/net/app-layer/coap
MAKE_WITH_DTLS = 1
MAKE_COAP_DTLS_WITH_CERT = 1
WERROR = 0

CONTIKI = ../..
include $(CONTIKI)/Makefile.include
