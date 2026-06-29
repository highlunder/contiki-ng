CONTIKI_PROJECT = p256m-bench

all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..

# p256-m: compact constant-time P-256 software implementation. We use a
# self-contained copy (vendor/p256-m-sa.c) derived from the in-tree mbedtls
# 3rdparty p256-m with its mbedtls/PSA coupling removed (drops the mbedtls/psa
# includes + the PSA RNG wrapper + the driver #if gate; local zeroize), so the
# integrator-supplied p256_generate_random (in p256m-bench.c) is used. Pure C.
CFLAGS += -I$(CURDIR)/vendor
PROJECT_SOURCEFILES += p256-m-sa.c
vpath p256-m-sa.c $(CURDIR)/vendor

ifneq ($(ITERS),)
  CFLAGS += -DBENCH_ITERS=$(ITERS)
endif

# Short build id stamped into the result printout for record-keeping. Defaults
# to the UTC date the hex is built; override with FW_ID=<id>. Always clean-build
# (rm -rf build) so the stamp is regenerated.
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

include $(CONTIKI)/Makefile.include
