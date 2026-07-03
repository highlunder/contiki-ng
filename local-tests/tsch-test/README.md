# Minimal TSCH network test (real hardware)

Goal: get the DK to **join a TSCH network** rooted at the Firefly, over the air —
the TSCH counterpart of the CSMA `1-net-join`. Once this works, the `-tsch`
benchmark firmwares (`../bench/`) have a network to run on.

```
  DK (1-net-join-tsch)  --TSCH assoc (channel-hopping)-->  Firefly
                                                            (border-router-tsch =
                                                             TSCH COORDINATOR + RPL root + gateway)
                                                              |  SLIP/UART (MAC-agnostic)
                                                              v
                                                            host: tunslip6 (tun0 = fd00::1)
```

The Firefly becomes the TSCH **coordinator** automatically: it is the RPL root
(once tunslip6 gives it the prefix), and the RPL→TSCH callback then calls
`tsch_set_coordinator(1)`. The DK scans channels for the coordinator's Enhanced
Beacons (EBs), associates, then joins the RPL DAG.

## Build
```
./build-tsch-test.sh
```
Produces `border-router-tsch.bin` (Firefly) and `1-net-join-tsch.hex` (DK). Both
are `MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1`.

## Run (WSL host)
1. **Flash the Firefly** (TSCH border-router):
   ```
   python3 ../../tools/cc2538-bsl/cc2538-bsl.py -e -w -v -b 460800 -a 0x00202000 \
       -p /dev/ttyUSB0 border-router-tsch.bin
   ```
2. **Bring up the gateway** (same as CSMA — SLIP is MAC-agnostic):
   ```
   make -C ../../examples/rpl-border-router TARGET=zoul BOARD=firefly \
       MAKE_MAC=MAKE_MAC_TSCH MAKE_WITH_ORCHESTRA=1 PORT=/dev/ttyUSB0 connect-router
   ```
   The Firefly should print it became RPL root, and TSCH should start as
   coordinator (`TSCH: starting as coordinator` / EBs going out).
3. **Flash the DK** (TSCH node) and reset:
   ```
   nrfjprog -f nrf52 --sectorerase --verify --program 1-net-join-tsch.hex
   nrfjprog -f nrf52 --reset
   ```

## What success looks like (DK console, COM5)
```
[INFO: TSCH      ] scanning on channel ...
[INFO: TSCH      ] association done ...      <- joined the TSCH network
...
[INFO: 1-net-join] === REACHABLE: joined the DAG, root is reachable ===
[INFO: 1-net-join] heartbeat: reachable. ...
```
Then `ping6 fd00::<dk-suffix>` from the host, and it appears under "Routing
links" in the border-router web UI (`curl -g "http://[fd00::1]/"`).

## Expect (this is the first real-hw TSCH bring-up)
- **Association takes longer than CSMA** — the DK channel-hops scanning for EBs;
  tens of seconds is normal, up to a couple of minutes on a marginal link.
- Both sides must share the default PAN (0xabcd) and hopping sequence (they do).
- In-emulator TSCH association works (cooja-ng, post-merge); real nRF↔CC2538 TSCH
  timing is new here, so expect one or two iterations. If the DK scans forever
  without associating, capture its console + the Firefly/tunslip6 log and we
  debug (likely EB reception / timeslot-timing on the nRF or CC2538).

SECURITY NOTICE: Test credentials only. Never use in production.
