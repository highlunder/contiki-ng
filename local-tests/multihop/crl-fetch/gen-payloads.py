#!/usr/bin/env python3
"""Generate the E10 on-wire CRL payload header (crl-payload.h).

Both payloads are REAL, verifiable CRLs over the same revoked set (serials
1..R) at the constrained profile of PLAN-revocation.md §0 (ECDSA-secp256r1 +
SHA-256, 2-byte serials, 8-byte AKID):

  c509  -- signed C509 CRL from the c509rev reference impl
           (idc509rev/c509rev/examples/crl_payload.rs), self-verified before
           emission, and byte-identical to what the on-device c509_crl_parse()
           consumes.
  x509  -- DER X.509 CRL minted with OpenSSL from a throwaway test CA over the
           same serials/reasons. This is the E2 baseline measured rather than
           modelled: the plan's analytic ~147+31R B is cross-checked against
           these bytes.

Neither payload is filler: the delivery result is about size, but using genuine
objects keeps the byte counts defensible and lets the same blob be parsed.

Determinism: the c509 arm is byte-reproducible (fixed key, RFC6979 signer). The
x509 arm is reproducible except for its signature: OpenSSL's ECDSA is randomized
(no RFC6979), so r/s -- and hence the DER length -- vary by +/-1-2 B run to run
(e.g. 3619/3620/3621 at R=100). Everything else is pinned (fixed CA key, fixed
thisUpdate/nextUpdate, fixed serials). The variation is ~0.05% of the payload and
cannot affect a delivery outcome; each run is self-consistent because the exact
length is stamped into crl-payload.h and reported by both endpoints. Switching
the X.509 arm to Ed25519 would make it deterministic but would no longer match
the C509 arm's ECDSA-P256 profile, so it is not done.

  ./gen-payloads.py --variant c509 --r 100 --out crl-payload.h

SECURITY NOTICE: Test credentials only. Never use in production.
"""
import argparse
import datetime
import pathlib
import subprocess
import sys
import tempfile

REPO = pathlib.Path(__file__).resolve().parents[3]
C509REV_MANIFEST = REPO.parent / "idc509rev" / "c509rev" / "Cargo.toml"
CARGO = pathlib.Path.home() / ".cargo" / "bin" / "cargo"
OPENSSL = "/usr/bin/openssl"

# Must match crl_payload.rs so both arms describe the same revoked set.
THIS_UPDATE = 1735776000
NEXT_UPDATE = 1736380800

# Fixed P-256 CA key for the X.509 arm. Generating a fresh key per invocation
# made the emitted DER non-deterministic: ECDSA signature values encode to
# different DER lengths run to run, so the same R could yield 3619 or 3620 bytes
# and two builds of the "same" cell would not be byte-identical. The C509 arm is
# deterministic (fixed key + RFC6979), and this arm must be too.
#
# SECURITY NOTICE: Test credentials only. Never use in production.
CA_KEY_PEM = """-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgTSoZ5vpvAClwvhey
V0+wDfELwTO/5E1lyAgV0z2DJvKhRANCAASm4lb1E6p54XkTxZhrt9opArKq5BgL
LDeB+bVSvgJWg4BROG/yPW9ChJPA4Fsv6/Y+FYkJtaehDVTfkr5w1t/D
-----END PRIVATE KEY-----
"""


def gen_c509(r):
    """Real signed C509 CRL bytes from the c509rev reference impl."""
    out = subprocess.run(
        [str(CARGO), "run", "-q", "--manifest-path", str(C509REV_MANIFEST),
         "--example", "crl_payload", "--", str(r)],
        capture_output=True, text=True, check=True)
    return bytes.fromhex(out.stdout.strip())


def _ts(unix):
    """openssl index.txt timestamp (2-digit year)."""
    return datetime.datetime.fromtimestamp(
        unix, datetime.timezone.utc).strftime("%y%m%d%H%M%SZ")


def _ts4(unix):
    """openssl -crl_lastupdate/-crl_nextupdate timestamp (4-digit year)."""
    return datetime.datetime.fromtimestamp(
        unix, datetime.timezone.utc).strftime("%Y%m%d%H%M%SZ")


def gen_x509(r):
    """Real DER X.509 CRL bytes from a throwaway OpenSSL test CA."""
    with tempfile.TemporaryDirectory() as d:
        d = pathlib.Path(d)
        key, cert = d / "ca.key", d / "ca.pem"
        key.write_text(CA_KEY_PEM)
        subprocess.run([OPENSSL, "req", "-new", "-x509", "-key", str(key),
                        "-out", str(cert), "-days", "365", "-sha256",
                        "-subj", "/CN=test crlocsp-ca"], check=True,
                       capture_output=True)

        # openssl ca's database: one 'R'(evoked) line per serial 1..R.
        expiry, revoked_at = _ts(NEXT_UPDATE), _ts(THIS_UPDATE)
        lines = []
        for i in range(1, r + 1):
            lines.append("R\t{}\t{},keyCompromise\t{:04X}\tunknown\t/CN=test-cert-{}"
                         .format(expiry, revoked_at, i, i))
        (d / "index.txt").write_text("\n".join(lines) + ("\n" if lines else ""))
        (d / "crlnumber").write_text("01\n")

        cnf = d / "ca.cnf"
        cnf.write_text(
            "[ca]\ndefault_ca = CA_default\n\n"
            "[CA_default]\n"
            "dir = {d}\n"
            "database = $dir/index.txt\n"
            "crlnumber = $dir/crlnumber\n"
            "certificate = {cert}\n"
            "private_key = {key}\n"
            "default_md = sha256\n"
            "default_crl_days = 7\n"
            "crl_extensions = crl_ext\n\n"
            "[crl_ext]\n"
            "authorityKeyIdentifier = keyid:always\n"
            .format(d=d, cert=cert, key=key))

        # `openssl ca -gencrl` emits PEM only; convert to DER (the on-wire form).
        pem, der = d / "crl.pem", d / "crl.der"
        # Pin thisUpdate/nextUpdate: by default openssl stamps them from the
        # wall clock, which makes the DER differ run to run. Pinning them also
        # puts both arms on the same validity window as crl_payload.rs.
        p = subprocess.run([OPENSSL, "ca", "-config", str(cnf), "-gencrl",
                            "-crl_lastupdate", _ts4(THIS_UPDATE),
                            "-crl_nextupdate", _ts4(NEXT_UPDATE),
                            "-out", str(pem), "-batch"],
                           capture_output=True, text=True)
        if p.returncode != 0:
            sys.exit("openssl ca -gencrl failed:\n" + p.stderr)
        subprocess.run([OPENSSL, "crl", "-inform", "PEM", "-in", str(pem),
                        "-outform", "DER", "-out", str(der)],
                       check=True, capture_output=True)
        return der.read_bytes()


def emit(path, variant, r, blob):
    body = []
    for i in range(0, len(blob), 12):
        row = ", ".join("0x{:02x}".format(b) for b in blob[i:i + 12])
        body.append("  " + row + ",")
    path.write_text(
        "/* GENERATED by gen-payloads.py -- do not edit.\n"
        " * variant={v} R={r} len={n} bytes\n"
        " * SECURITY NOTICE: Test credentials only. Never use in production.\n"
        " */\n"
        "#ifndef CRL_PAYLOAD_H_\n#define CRL_PAYLOAD_H_\n\n"
        "#include <stdint.h>\n\n"
        "#define CRL_PAYLOAD_VARIANT \"{v}\"\n"
        "#define CRL_PAYLOAD_R       {r}\n"
        "#define CRL_PAYLOAD_LEN     {n}\n\n"
        "static const uint8_t crl_payload[{n}] = {{\n{b}\n}};\n\n"
        "#endif /* CRL_PAYLOAD_H_ */\n"
        .format(v=variant, r=r, n=len(blob), b="\n".join(body)))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--variant", choices=["c509", "x509"], required=True)
    ap.add_argument("--r", type=int, required=True)
    ap.add_argument("--out", default="crl-payload.h")
    a = ap.parse_args()

    blob = gen_c509(a.r) if a.variant == "c509" else gen_x509(a.r)
    emit(pathlib.Path(a.out), a.variant, a.r, blob)
    print("{} R={} -> {} bytes -> {}".format(a.variant, a.r, len(blob), a.out))


if __name__ == "__main__":
    sys.exit(main())
