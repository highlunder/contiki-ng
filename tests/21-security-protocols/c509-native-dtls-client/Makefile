CONTIKI_PROJECT = c509-native-dtls-client
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MAKE_WITH_DTLS             = 1
MAKE_COAP_DTLS_WITH_CERT   = 1
MAKE_COAP_DTLS_WITH_CLIENT = 1
MAKE_COAP_DTLS_KEYSTORE    = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/services/c509
MODULES += os/lib

# native C509 test credentials are in the EDHOC header directory
CFLAGS += -I$(CONTIKI)/os/net/security/edhoc

include $(CONTIKI)/Makefile.include
