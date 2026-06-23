CONTIKI_PROJECT = ecc-bench

all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..
include $(CONTIKI)/Makefile.dir-variables

# Software lib/ecc.h backend (uECC) + curves.  When built with
# ECC_HW_BACKEND=cc310, os/services/ecc/Makefile.ecc excludes the software
# ecc.c and the nRF52840 platform links the CC310 backend instead.
MODULES += os/services/ecc

ifeq ($(ECC_HW_BACKEND),cc310)
  CFLAGS += -DECC_BENCH_BACKEND='"CC310 hardware"'
else
  CFLAGS += -DECC_BENCH_BACKEND='"software (uECC)"'
endif

# Curve under test. Default secp256r1; BP256=1 selects brainpoolP256r1
# (software backend only -- CC310 does not support brainpool).
# The uECC fork ships a full brainpoolP256r1 implementation but gates it behind
# uECC_SUPPORTS_brainpoolP256r1 (defaults 0 in uECC.h). The define must be
# global so BOTH uECC.c (curve code) and os/services/ecc/ecc.c (the ecc_enable
# branch) see it -- otherwise ecc_enable() rejects the curve and every op fails
# with res=ACQUIRE_FAILED / 0 cycles.
ifeq ($(BP256),1)
  CFLAGS += -DECC_BENCH_BP256
  CFLAGS += -DuECC_SUPPORTS_brainpoolP256r1=1
endif

# DEBUG=1 -> live per-op trace (start marker + result), for diagnosing a hang
# or watching progress on a slow backend.  ITERS=<n> overrides iteration count.
ifeq ($(DEBUG),1)
  CFLAGS += -DECC_BENCH_DEBUG=1
endif
ifneq ($(ITERS),)
  CFLAGS += -DBENCH_ITERS=$(ITERS)
endif

include $(CONTIKI)/Makefile.include
