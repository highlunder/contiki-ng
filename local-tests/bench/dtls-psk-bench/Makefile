CONTIKI_PROJECT = dtls-psk-bench
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

MAKE_WITH_DTLS              = 1
MAKE_COAP_DTLS_WITH_PSK     = 1
MAKE_COAP_DTLS_WITH_CLIENT  = 1
MAKE_COAP_DTLS_KEYSTORE     = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/lib

CFLAGS += -I$(CONTIKI)/local-tests/bench

# Short build id stamped into the startup + final printout for record-keeping.
# Defaults to the UTC build date; override FW_ID=. Clean-build to regenerate.
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

ifeq ($(LOCAL_TEST_DEBUG),1)
CFLAGS += -DLOCAL_TEST_DEBUG=1
endif

include $(CONTIKI)/Makefile.include
