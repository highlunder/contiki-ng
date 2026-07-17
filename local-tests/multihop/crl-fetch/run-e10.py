#!/usr/bin/env python3
"""E10 driver: build + run the multi-hop CRL-delivery sweep in cooja-ng-ge.

For each (variant, R, block) it regenerates the payload header, rebuilds both
endpoints and stages them under fw/; for each (hops, seed) it writes a line-
topology config and runs the emulator, saving the log under results/.

  ./run-e10.py --variants c509 x509 --r 100 --blocks 64 --hops 1 2 3 --seeds 1 7 13
  ./run-e10.py --summary            # re-parse results/ without running anything

Topology matches the M1 experiments (line, 50 m spacing, UDGM tx_range=55 ->
each node reaches only its neighbours; lossless). node 1 = CRL server + RPL root
+ TSCH coordinator, middle nodes = relays, last node = client.

SECURITY NOTICE: Test credentials only. Never use in production.
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys

HERE = pathlib.Path(__file__).resolve().parent
MULTIHOP = HERE.parent
CONTIKI = MULTIHOP.parent.parent
FW = MULTIHOP / "fw"
RESULTS = HERE / "results"
CONF = HERE / "conf"
RELAY_FW = FW / "relay.nrf"
TEST_RUNNER = "/home/joel/gemini_workspace/cooja-ng-ge/build/test_runner"

ARM = "/home/joel/toolchains/arm-gcc/bin"
TOOLS = ["CC=%s/arm-none-eabi-gcc" % ARM, "AS=%s/arm-none-eabi-gcc" % ARM,
         "LD=%s/arm-none-eabi-gcc" % ARM, "AR=%s/arm-none-eabi-ar" % ARM,
         "OBJCOPY=%s/arm-none-eabi-objcopy" % ARM, "NM=%s/arm-none-eabi-nm" % ARM]

FW_ID = "20260717"
SPACING = 50.0
# Sim-time budget: settle (150 s) + trials. Deeper paths need more slack, and a
# failing cell must be given enough time that "fail" means undeliverable rather
# than merely cut off.
TIMEOUT_BY_HOPS = {1: 400000, 2: 700000, 3: 1000000}


def sh(cmd, log):
    with open(log, "w") as f:
        return subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT).returncode


def build(variant, r, block):
    """Regenerate the payload header and rebuild both endpoints."""
    subprocess.run([sys.executable, str(HERE / "gen-payloads.py"),
                    "--variant", variant, "--r", str(r),
                    "--out", str(HERE / "crl-payload.h")], check=True)
    tag = "e10-%s-r%d-b%d" % (variant, r, block)
    for role in ("server", "client"):
        # Force a rebuild: the generated header changes per cell but the build
        # tree is shared, and CRL_BLOCK only enters via CFLAGS.
        sh(["make", "-C", str(HERE), "distclean"], "/dev/null")
        # MAKE_MAC_TSCH is mandatory: the shared relay firmware is TSCH, and the
        # stack silently defaults to CSMA -- a CSMA endpoint simply never
        # associates with the TSCH mesh (and a 1-hop CSMA-only run still
        # "passes", which is how this hid).
        rc = sh(["make", "-C", str(HERE), "ROLE=" + role, "TARGET=nrf",
                 "BOARD=nrf52840/dk", "LDFLAGS_WERROR=",
                 "MAKE_MAC=MAKE_MAC_TSCH", "FW_ID=" + FW_ID,
                 "CRL_BLOCK=%d" % block] + TOOLS,
                str(RESULTS / ("build-%s-%s.log" % (tag, role))))
        if rc != 0:
            sys.exit("build failed: %s %s (see results/build-%s-%s.log)"
                     % (tag, role, tag, role))
        src = HERE / "build" / "nrf" / "nrf52840" / "dk" / ("crl-fetch-%s.nrf" % role)
        dst = FW / ("%s-%s.nrf52840" % (tag, role))
        dst.write_bytes(src.read_bytes())
    return tag


def make_config(tag, hops, seed):
    """Line topology: server, (hops-1) relays, client."""
    nodes = [{"firmware": str(FW / ("%s-server.nrf52840" % tag)),
              "id": 1, "x": 0.0, "y": 0.0}]
    for i in range(1, hops):
        nodes.append({"firmware": str(RELAY_FW), "id": 1 + i,
                      "x": SPACING * i, "y": 0.0})
    nodes.append({"firmware": str(FW / ("%s-client.nrf52840" % tag)),
                  "id": hops + 1, "x": SPACING * hops, "y": 0.0})

    cfg = {
        "title": "E10 CRL fetch %s over %d-hop TSCH" % (tag, hops),
        "timeout_ms": TIMEOUT_BY_HOPS[hops],
        "seed": seed,
        "startup_delay_ms": 1000,
        "radiomedium": {"type": "udgm", "tx_range": 55.0,
                        "interference_range": 110.0,
                        "success_ratio_tx": 1.0, "success_ratio_rx": 1.0},
        "nodes": nodes,
        "test": {
            "description": (
                "Block-wise CoAP GET of /crl from the RPL root over a %d-hop line. "
                "Client prints [E10 trial]/[E10 SUMMARY]; E10-END marks completion. "
                "A cell that never prints E10-END is an undeliverable object at "
                "this depth (the headline outcome), not a harness error." % hops),
            "validators": [{"pattern": "E10-END", "node": hops + 1,
                            "min_count": 1}],
        },
    }
    path = CONF / ("emul-%s-%dhop-s%d.json" % (tag, hops, seed))
    path.write_text(json.dumps(cfg, indent=2) + "\n")
    return path


SUMMARY_RE = re.compile(
    r"\[E10 SUMMARY\].*variant=(\w+) R=(\d+) len=(\d+) block=(\d+) "
    r"trials=(\d+) ok=(\d+) fail=(\d+) mean_ms=(\d+) min_ms=(\d+) max_ms=(\d+)")
TRIAL_RE = re.compile(
    r"\[E10 trial\].*trial=(\d+) ok=(\d+) bytes=(\d+)/(\d+) blocks=(\d+) ms=(\d+)")


def parse(log_path):
    txt = pathlib.Path(log_path).read_text(errors="replace")
    trials = [dict(zip(("trial", "ok", "bytes", "expect", "blocks", "ms"),
                       map(int, m.groups()))) for m in TRIAL_RE.finditer(txt)]
    m = SUMMARY_RE.search(txt)
    summ = None
    if m:
        g = m.groups()
        summ = {"variant": g[0], "R": int(g[1]), "len": int(g[2]),
                "block": int(g[3]), "trials": int(g[4]), "ok": int(g[5]),
                "fail": int(g[6]), "mean_ms": int(g[7]), "min_ms": int(g[8]),
                "max_ms": int(g[9])}
    return trials, summ


def summarize():
    rows = []
    for log in sorted(RESULTS.glob("run-*.log")):
        m = re.match(r"run-e10-(\w+)-r(\d+)-b(\d+)-(\d)hop-s(\d+)\.log", log.name)
        if not m:
            continue
        variant, r, block, hops, seed = (m.group(1), int(m.group(2)),
                                         int(m.group(3)), int(m.group(4)),
                                         int(m.group(5)))
        trials, summ = parse(log)
        # No summary line => the client never finished: every trial undelivered.
        ok = summ["ok"] if summ else 0
        n = summ["trials"] if summ else 0
        rows.append({"variant": variant, "R": r, "block": block, "hops": hops,
                     "seed": seed, "ok": ok, "trials": n,
                     "blocks": trials[0]["blocks"] if trials else 0,
                     "len": summ["len"] if summ else 0,
                     "mean_ms": summ["mean_ms"] if summ else 0,
                     "finished": summ is not None})
    print("variant,R,block,hops,seed,len,blocks,ok,trials,mean_ms,finished")
    for r in rows:
        print("{variant},{R},{block},{hops},{seed},{len},{blocks},{ok},{trials},"
              "{mean_ms},{finished}".format(**r))
    return rows


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variants", nargs="+", default=["c509", "x509"])
    ap.add_argument("--r", type=int, nargs="+", default=[100])
    ap.add_argument("--blocks", type=int, nargs="+", default=[64])
    ap.add_argument("--hops", type=int, nargs="+", default=[1, 2, 3])
    ap.add_argument("--seeds", type=int, nargs="+", default=[1, 7, 13])
    ap.add_argument("--summary", action="store_true",
                    help="only re-parse results/, run nothing")
    a = ap.parse_args()

    RESULTS.mkdir(exist_ok=True)
    CONF.mkdir(exist_ok=True)
    if a.summary:
        summarize()
        return

    for block in a.blocks:
        for r in a.r:
            for variant in a.variants:
                tag = build(variant, r, block)
                for hops in a.hops:
                    for seed in a.seeds:
                        cfg = make_config(tag, hops, seed)
                        log = RESULTS / ("run-%s-%dhop-s%d.log" % (tag, hops, seed))
                        print("RUN %s hops=%d seed=%d ..." % (tag, hops, seed),
                              flush=True)
                        sh([TEST_RUNNER, "test", str(cfg)], log)
                        _, summ = parse(log)
                        print("    -> %s" % (summ if summ else "NO SUMMARY (undelivered)"),
                              flush=True)
    summarize()


if __name__ == "__main__":
    sys.exit(main())
