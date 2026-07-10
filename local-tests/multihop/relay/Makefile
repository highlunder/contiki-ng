CONTIKI_PROJECT = relay
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

# Opt-in dedicated-slot TSCH schedule (build with ORCHESTRA=1) to test whether the
# multi-hop reliability failures are specific to the 6TiSCH minimal single-shared-slot
# schedule (they are -- Orchestra's per-node slots avoid the relay self-collision).
ifdef ORCHESTRA
  MODULES += os/services/orchestra
endif

include $(CONTIKI)/Makefile.include
