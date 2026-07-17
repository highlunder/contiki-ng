CONTIKI_PROJECT = rev-ops-bench
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..
include $(CONTIKI)/Makefile.dir-variables

# Shared benchmark harness (bench-stats.h) + the self-contained c509 REVOCATION
# consume-path modules (no mbedTLS: uECC + SHA-256 only, matching the
# EDHOC/OSCORE stack). The revocation modules use the read-only c509-cbor-lite
# walker (NOT os/services/c509/cbor.h), so there is no cbor_major_type_t
# collision. x509_csr_sign_msg (from c509-csr-build.c) is linked only to
# synthesise a valid ECDSA-signed CRL at startup for the verify op.
CFLAGS += -I$(CONTIKI)/local-tests/bench
CFLAGS += -I$(CONTIKI)/os/services/c509
CFLAGS += -I$(CONTIKI)/os/net/security/micro-ecc
CFLAGS += -DuECC_OPTIMIZATION_LEVEL=4
CFLAGS += -DuECC_SQUARE_FUNC=1

vpath c509-crl.c              $(CONTIKI)/os/services/c509
vpath c509-ocsp.c             $(CONTIKI)/os/services/c509
vpath c509-ocsp-req.c         $(CONTIKI)/os/services/c509
vpath c509-rev-verify.c       $(CONTIKI)/os/services/c509
vpath c509-rev-verify-ecdsa.c $(CONTIKI)/os/services/c509
vpath c509-cbor-lite.c        $(CONTIKI)/os/services/c509
vpath c509-csr-build.c        $(CONTIKI)/os/services/c509
vpath uECC.c                  $(CONTIKI)/os/net/security/micro-ecc
CONTIKI_SOURCEFILES += c509-crl.c c509-ocsp.c c509-ocsp-req.c
CONTIKI_SOURCEFILES += c509-rev-verify.c c509-rev-verify-ecdsa.c c509-cbor-lite.c
CONTIKI_SOURCEFILES += c509-csr-build.c uECC.c

# NB: ed25519_verify.c (the Ed25519 rev-sig path) is deliberately NOT linked -- it
# pulls in mbedTLS SHA-512, which would defeat the point of a lean mbedTLS-free
# compute bench. This bench measures the ECDSA-secp256r1 verify path (uECC) only;
# the Ed25519 verify cost is the same primitive already characterised by the
# alt-kex benches. rev-ops-bench.c supplies a local, never-called ed25519_verify
# stub so c509-rev-verify.o (needed for c509_rev_locate_tbs) links.

# sha-256.c lives in os/lib.
MODULES += os/lib

# Repetitions per operation (override with ROP_ITERS=).
ROP_ITERS ?= 50
CFLAGS += -DROP_ITERS=$(ROP_ITERS)

# Inner batch size for the fast codec ops (parse/lookup/build) so the emulator's
# ~16us-granular rtimer (no DWT) resolves them. Override with ROP_BATCH=.
ROP_BATCH ?= 128
CFLAGS += -DROP_BATCH=$(ROP_BATCH)

# Short build id stamped into the result block for traceability. Defaults to the
# UTC build date; override FW_ID=. Always clean-build so the stamp regenerates.
FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

# Test id in the result block (config identifier). Override TEST_ID= to
# distinguish backend runs, e.g. TEST_ID=rev-ops-p256-cc310.
TEST_ID ?= rev-ops-p256-sw
CFLAGS += -DTEST_ID='"$(TEST_ID)"'

# Backend stamp. The revocation modules call uECC + SHA-256 DIRECTLY, so this
# bench measures the SOFTWARE path only (routing the sig verify through
# os/services/ecc for a CC310 figure is future work). Kept honest: always sw.
CFLAGS += -DECC_BACKEND_NAME='"software (uECC)"'

include $(CONTIKI)/Makefile.include
