CONTIKI_PROJECT = energest-node
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/simple-energest

# ROOT=1 builds the RPL-root / TSCH-coordinator image; otherwise a leaf.
ifeq ($(ROOT),1)
  CFLAGS += -DENERGEST_ROLE_ROOT=1
endif

include $(CONTIKI)/Makefile.include
