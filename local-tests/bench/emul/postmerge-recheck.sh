#!/bin/bash
# Post-upstream-merge re-check: rebuild all 10 DTLS/EDHOC apps against the merged
# tree and re-run the 5 TSCH-latency configs, then print the key timestamps so we
# can confirm the C509-vs-X.509 results are unaffected by the merge.
TC=/home/joel/toolchains/arm-gcc/bin
TESTS=/home/joel/gemini_workspace/contiki-ng/tests/21-security-protocols
R=/home/joel/gemini_workspace/cooja-ng-ge/build/test_runner
B=/home/joel/gemini_workspace/contiki-ng/local-tests/bench/emul
MK="TARGET=nrf BOARD=nrf52840/dk LDFLAGS_WERROR= MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 \
  CC=$TC/arm-none-eabi-gcc AS=$TC/arm-none-eabi-gcc LD=$TC/arm-none-eabi-gcc \
  AR=$TC/arm-none-eabi-ar OBJCOPY=$TC/arm-none-eabi-objcopy NM=$TC/arm-none-eabi-nm"

echo "###### REBUILD (against merged tree) ######"
for app in c509-native-dtls-server c509-native-dtls-client \
           x509-native-dtls-server x509-native-dtls-client \
           edhoc-oscore-x509-server edhoc-oscore-x509-client \
           edhoc-oscore-c5c-server  edhoc-oscore-c5c-client \
           edhoc-oscore-c5t-server  edhoc-oscore-c5t-client; do
  make -C "$TESTS/$app" $MK > "/tmp/postmerge_build_$app.log" 2>&1
  fw="$TESTS/$app/build/nrf/nrf52840/dk/$app.nrf"
  if [ -f "$fw" ]; then echo "OK   $app"; else echo "FAIL $app — see /tmp/postmerge_build_$app.log"; fi
done

echo "###### RE-RUN (5 configs) ######"
for cfg in dtls-x509 dtls-c509 edhoc-x509 edhoc-c5c edhoc-c5t; do
  $R test "$B/emul-$cfg-tsch.json" > "/tmp/postmerge_$cfg.log" 2>&1
  echo "--- $cfg ---"
  grep -hE "TEST PASSED|TEST FAILED" "/tmp/postmerge_$cfg.log" | head -1
done
