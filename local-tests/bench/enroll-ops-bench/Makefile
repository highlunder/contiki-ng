CONTIKI_PROJECT = enroll-ops-bench
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

# Shared benchmark harness (bench-stats.h) + the self-contained c509 enrollment
# modules (no mbedTLS: uECC + SHA-256 only, matching the EDHOC/OSCORE stack).
CFLAGS += -I$(CONTIKI)/local-tests/bench
CFLAGS += -I$(CONTIKI)/os/services/c509
CFLAGS += -I$(CONTIKI)/os/net/security/micro-ecc
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

vpath c509-csr-build.c $(CONTIKI)/os/services/c509
vpath c509-ca.c        $(CONTIKI)/os/services/c509
vpath c509-csr-parse.c $(CONTIKI)/os/services/c509
vpath uECC.c           $(CONTIKI)/os/net/security/micro-ecc
CONTIKI_SOURCEFILES += c509-csr-build.c c509-ca.c c509-csr-parse.c uECC.c

# sha-256.c lives in os/lib.
MODULES += os/lib

# Repetitions per operation (override with EOP_ITERS=).
EOP_ITERS ?= 50
CFLAGS += -DEOP_ITERS=$(EOP_ITERS)

# Short build id stamped into the result block for traceability. Defaults to the
# UTC build date; override FW_ID=. Always clean-build so the stamp regenerates.
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

# Test id in the result block (config identifier). Override TEST_ID= to
# distinguish backend runs, e.g. TEST_ID=enroll-ops-p256-cc310.
TEST_ID ?= enroll-ops-p256-sw
CFLAGS += -DTEST_ID='"$(TEST_ID)"'

# Backend stamp. The c509 enrollment modules (c509-csr-build/ca/csr-parse) call
# uECC + SHA-256 DIRECTLY, so this bench measures the SOFTWARE path only; the
# CC310 comparison for the underlying sign/verify primitives comes from the
# separate cc310-bringup ecc-bench (routing c509 signing through os/services/ecc
# for a CC310 enrollment-op figure is future work). Kept honest: always software.
CFLAGS += -DECC_BACKEND_NAME='"software (uECC)"'

include $(CONTIKI)/Makefile.include
