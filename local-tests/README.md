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

| # | `.hex` | what it exercises | setest scenario | server | status |
|---|--------|-------------------|-----------------|--------|--------|
| 1 | `1-net-join` | RPL join + connectivity (no crypto) | — | none (ping from host) | ✅ |
| 2 | `2-dtls-psk` | DTLS handshake + PSK | `psk` | `[fd00::1]:5686` | ✅ PASS |
| 3 | `3-dtls-x509` | DTLS handshake + X.509 | `A` | `[fd00::1]:5684` | ✅ PASS |
| 4 | `4-dtls-c509` | DTLS handshake + C509 (Type-2) | `B2` | `[fd00::1]:5687` | ⚠️ Type-2 gap |
| 5 | `5-edhoc-c5t` | EDHOC+OSCORE + C509 **c5t** | `D` | `[fd01::302:304:506:1]:5686`\* | 🔬 OTA bring-up |
| 6 | `6-edhoc-c5c` | EDHOC+OSCORE + C509 **c5c** | `Dc` | `[fd01::302:304:506:1]:5686`\* | 🔬 OTA bring-up |

DTLS rungs (2–4) have two `.hex` each: **`N-name.hex`** (release, INFO) and
**`N-name-dbg.hex`** (verbose RPL+DTLS+MAC — flash if a rung misbehaves). EDHOC
rungs (5–6) ship two ECC-backend builds: **`N-name.hex`** (software uECC) and
**`N-name-cc310.hex`** (nRF52840 CryptoCell hardware ECC, ~8–9× faster per P-256
op). Each boot printout stamps `ecc-backend: software | CC310 hardware`, so a
handshake log is self-identifying — flash both to compare whole-handshake
wall-clock over real RF. (CC310 needs the nRF5 SDK 17.1.0 blob; `build-edhoc-rungs.sh`
finds it at `../nRF5_SDK_17.1.0_ddde560`.)

> Rung 4 (C509 Type-2) is **staged**: the board presents a CA-issued Type-2 C509
> and verifies the peer in the CBOR domain, but stock `setest` B2 does standard
> X.509 verification (Type-2 signs over CBOR, so the reconstructed DER fails). It
> reaches certificate verification over the air (transport OK) but can't complete
> until the out-of-band verifier lands (`PLAN-c509-type2-dtls.md`, Task 10 / #16).

> \* **EDHOC rungs target a *different* endpoint, `fd01::302:304:506:1`.** The EDHOC scenarios
> can't be served by Python `setest` (lakers/aiocoap are CCS-only); they run the
> board's own EDHOC code as a **native responder**. For OTA that responder runs on
> a second host tun (`fd01::/64`) and IPv6 forwarding bridges it to the Firefly
> mesh — see `../../secure-endpoint-test-server/run-edhoc-gateway.sh`. This is
> where C509's real **wire-size** win shows (c5t sends a cert *hash*, c5c an inline
> cert — vs the full X.509 chain in DTLS). EDHOC rungs reuse the existing
> `edhoc-oscore-c5{t,c}-client` (already OTA-ready radio nodes) with only the
> server endpoint repointed via `EDHOC_CONF_SERVER_EP`.

## Build

```
./build-all.sh            # DTLS ladder (rungs 1–4) × {release, debug}
./build-edhoc-rungs.sh    # EDHOC rungs 5–6 (repointed to coap://[fd01::302:304:506:1])
```
Requires the ARM toolchain at `/home/joel/toolchains/arm-gcc` (build in the
container). DTLS sources live in `N-name/` subdirs; EDHOC rungs reuse the
`tests/21-security-protocols/edhoc-oscore-c5{t,c}-client` apps.

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
