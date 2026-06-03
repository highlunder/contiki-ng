CONTIKI_PROJECT = edhoc-uecc-mult-test

all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

MODULES += $(CONTIKI_NG_SECURITY_DIR)/edhoc

# Force level 4 + square (the configuration that fails on nRF52840 in cooja-ng)
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

# Expose uECC_vli_mult via the VLI API
CFLAGS += -DuECC_ENABLE_VLI_API=1

include $(CONTIKI)/Makefile.include
