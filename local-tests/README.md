# local-tests — Firefly-gateway OTA test ladder (nRF52840-DK)

A stepwise ladder of DK firmwares to flash **one at a time, in increasing order
of complexity**, over the real 2.4 GHz mesh rooted at the Zolertia Firefly
(see `../../secure-endpoint-test-server/FIREFLY-GATEWAY-README.md`). Each rung is
a **plain RPL node** that joins the Firefly's DAG over the air; the security
rungs then reach the `setest` server at `fd00::1` *through* the Firefly.

Every firmware prints a **boot banner** (`local-test-banner.h`) stating which
rung it is, its build variant, and its target server — so whichever `.hex` you
flashed, the console tells you what it is.

## The ladder

| # | `.hex` | what it exercises | setest scenario | server |
|---|--------|-------------------|-----------------|--------|
| 1 | `1-net-join` | RPL join + connectivity (no crypto) | — | none (ping it from the host) |
| 2 | `2-dtls-psk` | DTLS handshake + PSK | `psk` | `[fd00::1]:5686` |
| 3 | `3-dtls-x509` | DTLS handshake + X.509 | `A` | `[fd00::1]:5684` |
| 4 | `4-dtls-c509` | DTLS handshake + C509 (Type-2) | `B2` | `[fd00::1]:5687` |

Each rung has two `.hex`:
- **`N-name.hex`** — release (INFO logging; clean output).
- **`N-name-dbg.hex`** — debug (verbose RPL + DTLS + MAC logging; flash this if a
  rung misbehaves and you want to see why).

> Rung 4 (C509 Type-2) is **staged**: the board presents a CA-issued Type-2 C509
> and verifies the peer in the CBOR domain, but stock `setest` B2 serves a
> *self-signed* Type-2. Full interop needs the out-of-band verifier
> (`PLAN-c509-type2-dtls.md`, Task 10). Until then rung 4 exercises the C509
> credential + network path over the air but may not complete the handshake.

**EDHOC is not in this ladder yet:** the EDHOC scenarios (C/D/Dc) are served by a
*native* responder, not the Python `setest` (lakers/aiocoap can't do EDHOC).
Adding EDHOC-over-OTA rungs needs that responder wired to the tun — a later step.

## Build

```
./build-all.sh          # builds all rungs × {release, debug}, collects *.hex here
```
Requires the ARM toolchain at `/home/joel/toolchains/arm-gcc` (build in the
container). Sources live in `N-name/` subdirs; each is a normal Contiki-NG app
(radio node, no SLIP/border-router).

## Run each rung (on the WSL host, with the Firefly gateway up)

1. Bring up the gateway once (Firefly flashed + `tunslip6`): see
   `FIREFLY-GATEWAY-README.md`. Confirm `ping6 fd00::1` works.
2. Start the matching `setest` scenario bound on the tun endpoint, e.g. PSK:
   ```
   .venv/bin/python -m setest.server --scenario psk --bind fd00::1
   ```
3. Flash the rung and reset:
   ```
   nrfjprog -f nrf52 --sectorerase --verify --program 2-dtls-psk.hex
   nrfjprog -f nrf52 --reset
   ```
4. Watch the DK console (J-Link VCOM, e.g. COM5). Expect the banner, then
   `Joined the DAG`, then the handshake lines, then `=== N-name PASSED ===`.
   For rung 1, instead `ping6 <the fd00:: address it prints>` from the host.

**Timing:** the node waits for `node_is_reachable()` (DAG join + route) before
starting the handshake — so it self-paces; no fixed connect delay needed. Join
still takes ~30–60 s over real RF (see the gateway README).

SECURITY NOTICE: Test credentials only. Never use in production.
