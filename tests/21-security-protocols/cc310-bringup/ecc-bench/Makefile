CONTIKI_PROJECT = ecc-bench

all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..
include $(CONTIKI)/Makefile.dir-variables

# Software lib/ecc.h backend (uECC) + curves.  When built with
# ECC_HW_BACKEND=cc310, os/services/ecc/Makefile.ecc excludes the software
# ecc.c and the nRF52840 platform links the CC310 backend instead.
MODULES += os/services/ecc

# uECC build configuration -- THE SOFTWARE COLUMN DEPENDS ON THIS.
#
# uECC's own defaults are uECC_OPTIMIZATION_LEVEL=2 / uECC_SQUARE_FUNC=0 (see
# uECC.h), and neither this Makefile nor os/services/ecc/Makefile.ecc used to
# override them -- so the "software (uECC)" column measured the defaults. But
# EVERY deployed app in this tree (all the edhoc-*/enroll-* Makefiles, and
# local-tests/bench/enroll-ops-bench) builds uECC with LEVEL=4 + SQUARE_FUNC=1.
# The benchmark was therefore the only uECC build in the tree running the slow
# configuration, which made the CC310-vs-software gap look ~8x when the
# as-deployed gap is ~5.8x (measured: sign 161.2 ms default vs 117.0 ms at
# level 4, against CC310's 20.4 ms).
#
# Default to the as-deployed configuration so the software column means what a
# reader assumes. Reproduce the old default-uECC numbers with:
#   make ... UECC_OPT=2 UECC_SQUARE=0 FW_ID=<id>-uecc-default
UECC_OPT ?= 4
UECC_SQUARE ?= 1
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=$(UECC_OPT)
CFLAGS += -DuECC_SQUARE_FUNC=$(UECC_SQUARE)

# ECC_BENCH_ICACHE=0 leaves the nRF52840 NVMC instruction cache in the state the
# platform boots with. Historically that was DISABLED and no shipped app enabled
# it, so ICACHE=0 reproduces the as-deployed memory system of pre-2026-07-17
# firmware. Worth ~1.15x on uECC; CC310 is insensitive (its math is in the
# CryptoCell engine, not flash).
ECC_BENCH_ICACHE ?= 1
CFLAGS += -DECC_BENCH_ICACHE=$(ECC_BENCH_ICACHE)
ifeq ($(ECC_BENCH_ICACHE),0)
  # The nrf platform now enables the I-cache at boot (NRF_CONF_ENABLE_ICACHE),
  # so the app skipping its own enable is no longer enough to measure a cache-off
  # system -- the platform must be opted out too, or ICACHE=0 would silently
  # still run cached.
  CFLAGS += -DNRF_CONF_ENABLE_ICACHE=0
endif

# NB: a single-curve (secp256r1-only) build is NOT available here. This app pulls
# os/services/ecc, whose module-macros.h fixes the curve set to secp192r1 +
# secp256r1, and ecc.c calls uECC_secp192r1() unconditionally -- so dropping
# secp192r1 fails to compile, not merely to link. Reducing the curve set would
# require guarding those call sites in ecc.c first. Worth knowing: two curves are
# enabled here, which is what makes uECC_OPTIMIZATION_LEVEL=4 effective at all on
# ARM (uECC.h: level 4 "only has an effect ... where more than one curve is
# enabled"), so a single-curve build could actually be SLOWER.

ifeq ($(ECC_HW_BACKEND),cc310)
  CFLAGS += -DECC_BENCH_BACKEND='"CC310 hardware"'
else
  CFLAGS += -DECC_BENCH_BACKEND='"software (uECC)"'
endif

# Short build id stamped into the result printout for record-keeping. Defaults
# to the UTC date the hex is built; override with FW_ID=<id> (e.g. FW_ID=20260626b).
# Always clean-build (rm -rf build) so the stamp is regenerated.
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

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

# EXTRA_OPT must be appended AFTER the include: Makefile.include contributes the
# build's own -O2, and GCC honours the LAST -O on the command line. Adding it
# above would be silently overridden. Use EXTRA_OPT=-O3 to test a higher
# optimisation level (expect little: uECC's hot path is hand-written ARM asm).
CFLAGS += $(EXTRA_OPT)
