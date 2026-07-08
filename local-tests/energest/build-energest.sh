#!/bin/bash
# Build the 4 energest node firmwares (root/leaf x TSCH/CSMA) and stage under fw/.
# Uses the nrf52840 target (BOARD=dk); the cooja-ng-ge emulator maps the .nrf52840
# extension to the nRF52840-DK. Clean between builds because MAC/role flags change
# the whole config.
set -e
TC=/home/joel/toolchains/arm-gcc/bin
APP=/home/joel/gemini_workspace/contiki-ng/local-tests/energest
OUT=$APP/fw
mkdir -p "$OUT"
BASE="TARGET=nrf52840 BOARD=dk \
  CC=$TC/arm-none-eabi-gcc AS=$TC/arm-none-eabi-gcc LD=$TC/arm-none-eabi-gcc \
  AR=$TC/arm-none-eabi-ar OBJCOPY=$TC/arm-none-eabi-objcopy NM=$TC/arm-none-eabi-nm"
FW=build/nrf52840/dk/energest-node.nrf52840

build() { # $1=name  $2..=extra flags
  local name=$1; shift
  make -C "$APP" $BASE clean > /dev/null 2>&1
  make -C "$APP" $BASE "$@" > "/tmp/energest_build_$name.log" 2>&1
  if [ -f "$APP/$FW" ]; then cp "$APP/$FW" "$OUT/$name.nrf52840"; echo "OK   $name"; \
  else echo "FAIL $name — /tmp/energest_build_$name.log"; tail -8 "/tmp/energest_build_$name.log"; fi
}

build energest-root-tsch ROOT=1 MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1
build energest-leaf-tsch        MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1
build energest-root-csma ROOT=1
build energest-leaf-csma
