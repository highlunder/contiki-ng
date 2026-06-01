CONTIKI_PROJECT = edhoc-test-c509-server

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc
MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc/server

#uECC fast execution optimization
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

include $(CONTIKI)/Makefile.include
