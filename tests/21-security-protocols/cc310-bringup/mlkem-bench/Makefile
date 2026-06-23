CONTIKI_PROJECT = mlkem-bench

all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..

# Vendored ML-KEM (FIPS 203) reference + our randombytes shim.
PROJECTDIRS         += mlkem
PROJECT_SOURCEFILES += cbd.c fips202.c indcpa.c kem.c ntt.c poly.c polyvec.c \
                       reduce.c symmetric-shake.c verify.c
PROJECT_SOURCEFILES += randombytes-contiki.c
# The ref files include their siblings as "params.h", "randombytes.h", etc.,
# so the vendored dir must be on the include path.
CFLAGS += -I$(CURDIR)/mlkem

# Security level: MLKEM=512|768|1024 -> KYBER_K 2|3|4 (default ML-KEM-768).
MLKEM ?= 768
ifeq ($(MLKEM),512)
  CFLAGS += -DKYBER_K=2
else ifeq ($(MLKEM),768)
  CFLAGS += -DKYBER_K=3
else ifeq ($(MLKEM),1024)
  CFLAGS += -DKYBER_K=4
else
  $(error MLKEM must be 512, 768 or 1024)
endif

# The reference implementation keeps the matrix/polyvecs on the stack
# (ML-KEM-1024 keygen alone is ~8 KB); the 8 KB default startup stack is too
# tight, so widen it for all levels.
CFLAGS += -D__STACK_SIZE=32768

# DEBUG=1 -> live per-op trace; ITERS=<n> overrides the iteration count.
ifeq ($(DEBUG),1)
  CFLAGS += -DECC_BENCH_DEBUG=1
endif
ifneq ($(ITERS),)
  CFLAGS += -DBENCH_ITERS=$(ITERS)
endif

include $(CONTIKI)/Makefile.include
