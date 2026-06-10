CONTIKI_PROJECT = edhoc-native-c5t-client

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=15

include $(CONTIKI)/Makefile.include
