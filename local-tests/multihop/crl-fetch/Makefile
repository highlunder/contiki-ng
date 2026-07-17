# E10 -- multi-hop revocation-object delivery (LRev Tier 2).
#
# Build one endpoint at a time; the payload header must be generated first:
#   ./gen-payloads.py --variant c509 --r 100 --out crl-payload.h
#   make ROLE=server TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= ...
#
# The run-e10.sh driver does the generate/build/stage cycle for the whole sweep.

ifeq ($(ROLE),server)
  CONTIKI_PROJECT = crl-fetch-server
  CFLAGS += -DIS_NETWORK_ROUTING_ROOT=1
else
  CONTIKI_PROJECT = crl-fetch-client
  CFLAGS += -DIS_NETWORK_ROUTING_ROOT=0
endif
all: $(CONTIKI_PROJECT)

CONTIKI = ../../..

# crl-payload.h is generated into this directory by gen-payloads.py.
CFLAGS += -I.

MODULES += os/net/app-layer/coap

# A block-wise fetch is many CON exchanges; at depth each needs time to traverse
# and be acked, so the stock 3 s deadline expires mid-transfer (the M1 multi-hop
# tuning). Must be -D, not project-conf.h: coap-constants.h is included ahead of
# project-conf.h in the coap TUs.
CFLAGS += -DCOAP_RESPONSE_TIMEOUT=25 -DCOAP_MAX_RETRANSMIT=6

# Block-wise block size (RFC 7959 power of two). Both endpoints MUST agree:
# a mismatch silently truncates the transfer.
CRL_BLOCK ?= 64
CFLAGS += -DCRL_BLOCK=$(CRL_BLOCK)

# Repeats per configuration -- delivery is a rate, so a single fetch says little.
CRL_TRIALS ?= 3
CFLAGS += -DCRL_TRIALS=$(CRL_TRIALS)

# Settle before the first fetch (seconds of sim time). Same at every hop count so
# it is a control, not a per-cell variable.
CRL_START_DELAY_S ?= 150
CFLAGS += -DCRL_START_DELAY_S=$(CRL_START_DELAY_S)

# CRL_DIAG=1 raises MAC/RPL logging (association + parent selection).
ifdef CRL_DIAG
  CFLAGS += -DCRL_DIAG=1
endif

FW_ID ?= $(shell date -u +%Y%m%d)
CFLAGS += -DFW_BUILD_ID='"$(FW_ID)"'

include $(CONTIKI)/Makefile.include
