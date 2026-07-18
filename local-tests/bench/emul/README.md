# Emulated-nRF benchmarks (hardware ↔ simulation, then scale)

Run the **same** bench firmware that flashes on the DK inside the cooja-ng
emulator (cycle-level nRF52840), so the crypto+protocol timing is comparable to
hardware — then scale to node counts hardware can't reach. Enabled by the
cooja-ng ARM emulation speedups (nRF now ~20× real-time for simple nodes; ~7×
for the crypto-heavy EDHOC handshake).

**Software only:** cooja-ng does not emulate the CC310 CryptoCell, so only the
`sw` (uECC) bench firmwares run here. `sw` runs on both hw and sim, so it's the
cross-check firmware; CC310 numbers stay hardware-only.

## Run
```
./run-emul-bench.sh                 # 30 iters (default), UDGM lossless
BENCH_ITERS=100 ./run-emul-bench.sh # match the hw iteration count
```
Builds the nRF EDHOC responder + the c5t sw bench client (pointed at the
responder's emulated address) and runs `emul-edhoc-c5t.json` (server=node 2,
client=node 1). Prints the same `[BENCH … FINAL]` median/p95 line — in simulated
time. Compare to the hardware line in `../BENCH-RESULTS-LOG.md`.

## First result (see ../BENCH-RESULTS-LOG.md)
Emulator sw c5t median **956 ms** vs hardware **689 ms** ≈ **1.4×**, same tight sd
(~42 ms).

**Why (measured, not a calibration fudge):** radio loss is zero (UDGM 1.0/1.0),
and the whole gap is the **responder's crypto**. `run-emul-profile.sh` builds
both nodes with `EDHOC_PROFILE_CYCLES` and times every ECC op (rtimer µs — the
emulator has no DWT, so cycles read 0). Each emulated nRF pays ~381 ms of uECC
P-256; the responder's keygen+ECDH+sign (272 ms) sits on the client's critical
path. On *hardware* the responder is a **native x86** server (crypto ≈ free), so
only the client's 379 ms ECC counts: `379 + ~310 ms RF = 689 ms` exactly. The
client ECC is cycle-identical hw↔emul and the RF floor matches to ~2 %. So the
emulator is *more honest* (both peers constrained), not miscalibrated — a real
device↔device EDHOC handshake is ~955 ms, not ~689 ms. See
`run-emul-profile.sh` + `emul-profile.log`.

## The address gotcha (important)
An emulated nRF node's IPv6 address is **FICR-derived**, NOT the native-cooja
`…202:2:2:2`, and NOT the `[PKT]` radio-trace rendering (a broken artifact — it
shows every node ending in `…cef4`). Use the node's own firmware log line:
`Tentative link-local IPv6 address: fe80::<IID>` → global `fd00::<IID>`. It is
**deterministic per node id**: node 2 = `fd00::f6ce:3602:e3e9:2`. The bench
client's `EDHOC_CONF_SERVER_EP` is built to that (the run script does it).

## Scaling to bigger networks (next)
`emul-edhoc-c5t.json` uses UDGM lossless with 2 nodes. To scale:
- Add more client nodes (each needs the responder's address — same for all since
  the responder is node 2) and position them multi-hop (nodes > `tx_range` apart,
  chained), so `hops` rises.
- Swap `radiomedium` UDGM → the Gilbert-Elliott plugin
  (`build/plugins/gilbert_elliott_medium.so`, `CSIM_GE_*` env) for burst loss.
- Measure completion / median / p95 as the network grows — the story hardware
  can't give. (Sequential emulator: wall-clock scales ~linearly with node count;
  at ~7× for 2 crypto nodes, ~10 nodes is still near real-time.)

SECURITY NOTICE: Test credentials only. Never use in production.
