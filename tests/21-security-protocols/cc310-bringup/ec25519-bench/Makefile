CONTIKI_PROJECT = ec25519-bench

all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..
include $(CONTIKI)/Makefile.dir-variables

# CC310 hardware backend: provides ecc_init() (nrf_crypto_init) and the
# BASEPRI-isolated ecc_session_begin()/_end() used to seed the CC310 TRNG.
# CC310_ECC_25519=1 additionally wires the Curve25519 + Ed25519 nrf_crypto
# backends (see arch/cpu/nrf52840/Makefile.cc310-crypto).  This bench is
# CC310-only -- uECC has no 25519 software path.
ECC_HW_BACKEND  = cc310
CC310_ECC_25519 = 1
MODULES += os/services/ecc

# DEBUG=1 -> live per-op trace; ITERS=<n> overrides the iteration count.
ifeq ($(DEBUG),1)
  CFLAGS += -DECC_BENCH_DEBUG=1
endif
ifneq ($(ITERS),)
  CFLAGS += -DBENCH_ITERS=$(ITERS)
endif

include $(CONTIKI)/Makefile.include
