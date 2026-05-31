#!/bin/sh
# Build c509-client-border firmware for nRF52840-DK with the local ARM toolchain.
export PATH=/home/joel/toolchains/arm-gcc/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
exec make TARGET=nrf52840 BOARD=dk "$@"
