CONTIKI_PROJECT = edhoc-oscore-c5t-server

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += os/net/security/edhoc
MODULES += os/net/security/edhoc/server
MODULES += os/net/security/oscore

CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# Opt-in dedicated-slot TSCH schedule (build ORCHESTRA=1); see local-tests/multihop/relay/Makefile.
ifdef ORCHESTRA
  MODULES += os/services/orchestra
endif

include $(CONTIKI)/Makefile.include
