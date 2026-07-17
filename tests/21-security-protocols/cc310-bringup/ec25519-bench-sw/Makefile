CONTIKI_PROJECT = ec25519-bench-sw

all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..

# Vendored Monocypher (X25519 + standard SHA-512 Ed25519), portable software.
PROJECTDIRS         += monocypher
PROJECT_SOURCEFILES += monocypher.c monocypher-ed25519.c
# Monocypher's optional module includes "monocypher.h" as a sibling.
CFLAGS += -I$(CURDIR)/monocypher

# DEBUG=1 -> live per-op trace; ITERS=<n> overrides the iteration count.
# (NB: the override variable is ITERS, not BENCH_ITERS.)
ifeq ($(DEBUG),1)
  CFLAGS += -DECC_BENCH_DEBUG=1
endif
ifneq ($(ITERS),)
  CFLAGS += -DBENCH_ITERS=$(ITERS)
endif

# Firmware build id, stamped into the SUMMARY line for traceability (matches
# ecc-bench / enroll-ops). Defaults to the UTC build date; override FW_ID=<id>.
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

include $(CONTIKI)/Makefile.include
