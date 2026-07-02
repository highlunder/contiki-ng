CONTIKI_PROJECT = 1-net-join
all: $(CONTIKI_PROJECT)

CONTIKI = ../..

# Shared boot banner (local-tests/local-test-banner.h)
CFLAGS += -I$(CONTIKI)/local-tests

# Debug variant: `make ... LOCAL_TEST_DEBUG=1` (build-all.sh does both)
ifeq ($(LOCAL_TEST_DEBUG),1)
CFLAGS += -DLOCAL_TEST_DEBUG=1
endif

include $(CONTIKI)/Makefile.include
