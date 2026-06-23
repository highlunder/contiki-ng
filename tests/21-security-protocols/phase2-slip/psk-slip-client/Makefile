CONTIKI_PROJECT = psk-slip-client
all: $(CONTIKI_PROJECT)

CONTIKI = ../../../..

MAKE_WITH_DTLS              = 1
MAKE_COAP_DTLS_WITH_PSK     = 1
MAKE_COAP_DTLS_WITH_CLIENT  = 1
MAKE_COAP_DTLS_KEYSTORE     = MAKE_COAP_DTLS_KEYSTORE_SIMPLE

MODULES += os/net/app-layer/coap
MODULES += os/lib

# Compile the nRF native-USB CDC stack so console logs can use it (see
# project-conf.h: logs -> nRF USB, SLIP -> UART0/J-Link VCOM). This is a Make
# variable (gates arch/cpu/nrf52840/usb/Makefile.usb), not just a C macro.
NRF52840_NATIVE_USB = 1

# Phase-2 single-board uplink: the board is its own RPL root reachable over a
# SLIP serial link (host runs tunslip6). The embedded border-router module is
# auto-initialised from contiki-main.c when included.
include $(CONTIKI)/Makefile.dir-variables
MODULES += $(CONTIKI_NG_SERVICES_DIR)/rpl-border-router

CFLAGS += -DCOOJA_MTARCH_STACKSIZE=65536

include $(CONTIKI)/Makefile.include
