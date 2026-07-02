CONTIKI_PROJECT = 4-dtls-c509
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

MAKE_WITH_DTLS             = 1
MAKE_COAP_DTLS_WITH_CERT   = 1
MAKE_COAP_DTLS_WITH_CLIENT = 1
MAKE_COAP_DTLS_KEYSTORE    = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/services/c509
MODULES += os/services/ecc
MODULES += os/lib

# native C509 test credentials are in the EDHOC header directory
CFLAGS += -I$(CONTIKI)/os/net/security/edhoc
CFLAGS += -I$(CONTIKI)/local-tests

ifeq ($(LOCAL_TEST_DEBUG),1)
CFLAGS += -DLOCAL_TEST_DEBUG=1
endif

include $(CONTIKI)/Makefile.include
