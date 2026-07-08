#!/bin/bash
# Re-measure the 5 TSCH-latency configs after the nrfx submodule update
# (v2.10.0 -> v3.12.1, pulled in by the upstream merge). Distclean + full rebuild
# of all 10 apps on the shared nrf platform, then run the 5 configs and print the
# key timestamps. The absolute latency shifts slightly with the nrfx radio/timer
# driver version; message sizes and ordering are invariant.
TC=/home/joel/toolchains/arm-gcc/bin
TESTS=/home/joel/gemini_workspace/contiki-ng/tests/21-security-protocols
R=/home/joel/gemini_workspace/cooja-ng-ge/build/test_runner
B=/home/joel/gemini_workspace/contiki-ng/local-tests/bench/emul
MK="TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 \
  CC=$TC/arm-none-eabi-gcc AS=$TC/arm-none-eabi-gcc LD=$TC/arm-none-eabi-gcc \
  AR=$TC/arm-none-eabi-ar OBJCOPY=$TC/arm-none-eabi-objcopy NM=$TC/arm-none-eabi-nm"

echo "###### DISTCLEAN + REBUILD (nrfx 3.12.1) ######"
for app in c509-native-dtls-server c509-native-dtls-client \
           x509-native-dtls-server x509-native-dtls-client \
           edhoc-oscore-x509-server edhoc-oscore-x509-client \
           edhoc-oscore-c5c-server  edhoc-oscore-c5c-client \
           edhoc-oscore-c5t-server  edhoc-oscore-c5t-client; do
  make -C "$TESTS/$app" TARGET=nrf distclean > /dev/null 2>&1
  make -C "$TESTS/$app" $MK > "/tmp/remeasure_build_$app.log" 2>&1
  fw="$TESTS/$app/build/nrf/nrf52840/dk/$app.nrf"
  [ -f "$fw" ] && echo "OK   $app" || { echo "FAIL $app"; tail -5 "/tmp/remeasure_build_$app.log"; }
done

echo "###### RUN + EXTRACT ######"
for cfg in dtls-x509 dtls-c509 edhoc-x509 edhoc-c5c edhoc-c5t; do
  $R test "$B/emul-$cfg-tsch.json" > "/tmp/remeasure_$cfg.log" 2>&1
  echo "--- $cfg ---"
  grep -hE "TEST PASSED|TEST FAILED" "/tmp/remeasure_$cfg.log" | head -1
  grep -hE "Connecting to server over CoAPS \(handshake 1|handshake 1 complete|message_1 generation|MSG2 sz|MSG3 sz|EDHOC finished" "/tmp/remeasure_$cfg.log" | grep -viE "DBG"
done
