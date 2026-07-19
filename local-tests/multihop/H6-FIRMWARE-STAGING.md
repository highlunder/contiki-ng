# H6 — Real-RF multi-hop firmware staging (LICE-followup Phase-2)

Prep for **Exp H6** (`PLAN-c509-lice-followup.md §10.6`): reproduce the cooja-ng
multi-hop C509-vs-X.509 delivery/latency gap on **real silicon**, forcing a line
topology among co-located boards with the `TOPO_ROLE` source-role filter (no
physical separation, no attenuators). Headline to confirm: **c5t completes at
every hop count; x5c/X.509 fails at 3 hops** (emulation: `MULTIHOP-M1-RESULTS.md`).

## Build all firmware
```
./stage-h6-firmware.sh            # -> fw-hw/*.hex   (ARM=<dir> to override toolchain)
```
The script builds one image per (app, board, `TOPO_ROLE`).

> **Gotcha it handles for you:** `TOPO_ROLE` is passed via the `CFLAGS` env var,
> and a plain rebuild does **not** notice an env-`CFLAGS` change (`make` says
> "Nothing to be done") — a stale image *without* the filter would ship and every
> node would hear every other node (no hops). The script therefore `make clean`s
> before **every** per-role build and objcopy's each `.hex` immediately, before
> the next role overwrites the build tree. If you build by hand, `make clean`
> between roles.

## Node layout (2 DK + 3 dongles → up to a 4-node / 3-hop line)
`TOPO_ROLE=n` fixes the address to `02:…:0n` and drops any frame whose source
role is not `n±1`, so only adjacent roles hear each other.

| hops | root (DK, role 1) | relays (dongle) | leaf/DUT (DK) |
|------|-------------------|-----------------|----------------|
| 1    | `*-server-r1-dk`  | —               | `*-leaf-r2-dk` |
| 2    | `*-server-r1-dk`  | `relay-r2-dongle` | `*-leaf-r3-dk` |
| 3    | `*-server-r1-dk`  | `relay-r2-dongle`, `relay-r3-dongle` | `*-leaf-r4-dk` |

Run the **c5t** arm (`c5t-server` + `c5t-leaf`, the instrumented bench: reads
`[BENCH … FINAL] … (ms)` on the leaf serial) and the **x5c** arm
(`x5c-server` + `x5c-leaf`) at each hop count. Relays are identical across arms.

## Flashing
- **DK** (root, leaf): J-Link — `nrfjprog --program fw-hw/<name>.hex --chiperase -r`
  (or via the WSL/Windows split per the CC310 bring-up notes). Read the leaf DK
  serial for the `[BENCH]` line / EDHOC completion.
- **Dongle** (relays): DFU — `nrfutil` per `reference_nrf_dongle_dfu`
  (`nrfutil nrf5sdk-tools pkg generate --hw-version 52 --sd-req 0x00 \
  --application fw-hw/relay-rN-dongle.hex … relay-rN.zip`, then
  `nrfutil dfu usb-serial -pkg relay-rN.zip -p <COM>`). The relay has no useful
  serial output; it only forwards.

## Metric / expected result
Per hop count, record the leaf's handshake completion (`[BENCH … FINAL] (ms)` for
c5t) and pass/fail. Expect the emulator ordering: c5t ≪ x5c latency, and **x5c
fails to deliver at 3 hops** while c5t completes — the real-RF counterpart of
`table:multihop` and the direct feed to the paper's `sec:eval-hw` Phase-2
paragraph. Log verbatim into `BENCH-RESULTS-LOG.md` with the DK serial + date.

## Firmware manifest (fw-hw/)
| image | app | board | role | arm |
|-------|-----|-------|------|-----|
| `c5t-server-r1-dk`  | `edhoc-oscore-c5t-server`  | DK     | 1 | c5t root |
| `x5c-server-r1-dk`  | `edhoc-oscore-x509-server` | DK     | 1 | x5c root |
| `relay-r2-dongle`   | `relay`                    | dongle | 2 | both |
| `relay-r3-dongle`   | `relay`                    | dongle | 3 | both |
| `c5t-leaf-r{2,3,4}-dk` | `edhoc-c5t-bench`       | DK     | 2/3/4 | c5t leaf (1/2/3 hop) |
| `x5c-leaf-r{2,3,4}-dk` | `edhoc-oscore-x509-client` | DK  | 2/3/4 | x5c leaf (1/2/3 hop) |
