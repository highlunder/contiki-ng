# tsch-bulk — pure-transport fragmentation probe (CSMA vs TSCH)

Find **where a multi-fragment payload stops getting through**, with no DTLS/CoAP
in the way. The DK joins the RPL DODAG and sends **plain UDP** datagrams of
increasing size to a host echo server, reporting round-trip success per size.
This isolates the 6LoWPAN-fragmentation / MAC transport limit from the handshake
logic — the open question for why cert-DTLS completes on CSMA but not on
minimal-schedule TSCH.

`~90 B` fits one 6LoWPAN fragment on 802.15.4, so `frags ≈ ceil(size/90)`. The
DTLS certificate flight is ~11 fragments (~800–1000 B), so the 720–1040 B rows
bracket it.

## Run
Same gateway as the benches (Firefly RPL root + `tunslip6`, `tun0 = fd00::1`).

1. **Host** (behind the gateway, same box as setest):
   ```
   python3 udp-echo.py            # binds [::]:7777, echoes + logs received size
   ```
2. **DK**: flash `bulk-tsch.hex` (or `bulk-csma.hex` for the baseline) — build with
   `./build-bulk.sh`. Watch the DK serial (e.g. `watch-serial.ps1`).

## Reading it
- **DK log**: `[BULK] size=720 frags~8 ok=6/8 rtt_avg_ms=…` — round-trip success
  (uplink **and** downlink) at each size.
- **Host log**: `HH:MM:SS.mmm recv 720 B <- fd00::… -> echo` — what the **uplink**
  delivered.

Cross-reference to localise the failure direction:
- host logs `recv 720` but DK `ok=0/8` at 720 → **uplink OK, downlink (echo) drops**
  (the direction the *server's* cert flight travels — the suspected DTLS blocker).
- host never logs 720 → **uplink drops** first.

Run `bulk-csma.hex` and `bulk-tsch.hex` back-to-back: CSMA should carry the full
sweep (it carries the 11-fragment cert flight fine), TSCH will show the wall.

SECURITY NOTICE: Test credentials only. Never use in production.
