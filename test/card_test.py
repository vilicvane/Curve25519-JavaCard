#!/usr/bin/env python3
"""On-card test driver for the reconstructed org.suut.javacard.pki.curve25519 package.

The driver talks to ``Curve25519TestApplet`` through ``test/card/ApduRunner.java``, which keeps a
single PC/SC session open (GlobalPlatformPro closes the session after every invocation, so an
applet cannot be driven APDU by APDU with ``gp -a``).

Every cryptographic result is compared against ``test/ref25519.py``, a standalone RFC 8032 /
RFC 7748 implementation. The Ed25519 variant that the JCOPX package implements is not documented,
so the signature check reports which of the plausible variants (plain Ed25519 over the input,
Ed25519ph over SHA-512 of the input, Ed25519ph over the input as a prehash) matches.

Usage:

    python3 test/card_test.py [--aid AID] [--dir DIR] [--self-check] [--timing]

``--aid``     applet AID, default F043555256450101
``--dir``     Windows directory used to compile and run ApduRunner
``--self-check`` only run the reference vectors, do not touch the card
``--timing``  also report how long the operations took on the card
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ref25519

DEFAULT_AID = "F043555256450101"
DEFAULT_DIR = r"C:\Users\vilicvane\AppData\Local\Temp\curve25519-test\card"
WINDOWS_JDK = "/mnt/c/Program Files/Java/jdk-11/bin"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APDU_RUNNER_SOURCE = os.path.join(REPO_ROOT, "test", "card", "ApduRunner.java")

# RFC 8032 section 7.1, test 1.
EDDSA_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
EDDSA_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)

# RFC 7748 section 6.1.
X25519_SCALAR = bytes.fromhex(
    "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
)
X25519_PUBLIC = bytes.fromhex(
    "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
)
X25519_PEER_PUBLIC = bytes.fromhex(
    "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
)
X25519_SHARED = bytes.fromhex(
    "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
)

MESSAGE = hashlib.sha512(b"curve25519-javacard on-card test").digest()[:32]

INS_GENERATE_PAIR = 0x01
INS_GET_PUBLIC = 0x10
INS_GET_PRIVATE = 0x11
INS_SET_PUBLIC = 0x12
INS_SET_PRIVATE = 0x13
INS_SIGN = 0x30
INS_VERIFY = 0x40
INS_EXCHANGE = 0x50
INS_INFO = 0x60

P1_EDDSA = 0x00
P1_X25519 = 0x01


def fs_path(path):
    """Translate a Windows path to the path this process can open.

    ``--dir`` defaults to a Windows path because ``ApduRunner`` runs under the Windows JDK. When
    this script itself runs under WSL, the same directory has to be addressed as ``/mnt/c/...``,
    otherwise ``os.makedirs`` happily creates a directory literally named ``C:\\Users\\...`` inside
    the repository.
    """
    if len(path) >= 3 and path[1] == ":" and path[2] in "\\/":
        if os.path.isdir("/mnt/" + path[0].lower()):
            return "/mnt/" + path[0].lower() + "/" + path[3:].replace("\\", "/")
    return path


class CardError(Exception):
    pass


class Runner(object):
    """One ApduRunner process, i.e. one selected applet session."""

    def __init__(self, aid, directory):
        self.directory = directory
        java = os.path.join(WINDOWS_JDK, "java.exe")
        self.process = subprocess.Popen(
            [java, "-cp", ".", "ApduRunner", aid],
            cwd=fs_path(directory),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            bufsize=1,
        )
        # ApduRunner prints diagnostics on stderr (# terminal/# atr/# selected) and results on
        # stdout, so wait for the "# selected" line before sending anything.
        self.select_line = self._await_selection()

    def _await_selection(self):
        while True:
            line = self.process.stderr.readline()
            if not line:
                return ""
            line = line.strip()
            if line:
                print("  " + line)
            if "selected" in line:
                return line

    def send(self, apdu):
        started = time.perf_counter()
        data, sw = self._exchange(apdu)
        self.last_ms = (time.perf_counter() - started) * 1000.0
        return data, sw

    def _exchange(self, apdu):
        self.process.stdin.write(apdu.hex().upper() + "\n")
        self.process.stdin.flush()
        line = self.process.stdout.readline()
        if not line:
            stderr = self.process.stderr.read()
            raise CardError("ApduRunner exited: " + stderr.strip())
        line = line.strip()
        if not line.startswith("DATA="):
            raise CardError("unexpected runner output: " + line)
        data_text, sw_text = line.split(" SW=")
        data = bytes.fromhex(data_text[len("DATA=") :])
        return data, int(sw_text, 16)

    def close(self):
        try:
            self.process.stdin.close()
        except Exception:
            pass
        self.process.wait(timeout=10)


def apdu(ins, p1=0, p2=0, data=b""):
    if data:
        return bytes([0x00, ins, p1, p2, len(data)]) + data + b"\x00"
    return bytes([0x00, ins, p1, p2, 0x00])


class Report(object):
    def __init__(self, show_timing=False):
        self.results = []
        self.timings = []
        self.show_timing = show_timing

    def check(self, name, ok, detail=""):
        self.results.append((name, bool(ok), detail))
        print(("  PASS  " if ok else "  FAIL  ") + name + (("  " + detail) if detail else ""))
        return ok

    def info(self, text):
        print("  ----  " + text)

    def timing(self, name, ms):
        self.timings.append((name, ms))

    def failed(self):
        return [r for r in self.results if not r[1]]

    def summary(self):
        if self.show_timing and self.timings:
            print()
            print("timings (round trip incl. PC/SC, ms):")
            for name, ms in self.timings:
                print("  %-38s %8.1f" % (name, ms))
        failed = self.failed()
        print()
        print("%d checks, %d failed" % (len(self.results), len(failed)))
        for name, _, detail in failed:
            print("  failed: " + name + (("  " + detail) if detail else ""))
        return not failed


def expect(report, name, data, sw, expected_data, expected_sw=0x9000):
    if sw != expected_sw:
        return report.check(name, False, "SW=%04X" % sw)
    if expected_data is not None and data != expected_data:
        return report.check(
            name,
            False,
            "got " + data.hex().upper() + " want " + expected_data.hex().upper(),
        )
    return report.check(name, True)


def run_card_tests(runner, report):
    # --- diagnostics -------------------------------------------------------------------------
    data, sw = runner.send(apdu(INS_INFO))
    if sw == 0x9000 and len(data) == 12:
        report.info(
            "memory types eddsa=%d/%d x25519=%d/%d sizes=%d/%d/%d/%d initialised=%s"
            % (
                data[0], data[1], data[2], data[3],
                data[4], data[5], data[6], data[7],
                ",".join(str(b) for b in data[8:12]),
            )
        )
    else:
        report.check("info", False, "SW=%04X len=%d" % (sw, len(data)))

    # --- EdDSA key import and export ----------------------------------------------------------
    data, sw = runner.send(apdu(INS_SET_PRIVATE, P1_EDDSA, data=EDDSA_SEED))
    expect(report, "import EdDSA seed", data, sw, b"")

    data, sw = runner.send(apdu(INS_GET_PRIVATE, P1_EDDSA))
    expect(report, "read back EdDSA seed", data, sw, EDDSA_SEED)

    data, sw = runner.send(apdu(INS_SET_PUBLIC, P1_EDDSA, data=EDDSA_PUBLIC))
    expect(report, "import EdDSA public key", data, sw, b"")

    data, sw = runner.send(apdu(INS_GET_PUBLIC, P1_EDDSA))
    expect(report, "read back EdDSA public key", data, sw, EDDSA_PUBLIC)

    # --- signing ------------------------------------------------------------------------------
    data, sw = runner.send(apdu(INS_SIGN, data=MESSAGE))
    signature = data
    report.timing("sign (EdDSA)", runner.last_ms)
    if sw != 0x9000:
        report.check("sign", False, "SW=%04X" % sw)
        return
    report.check("sign returns 64 bytes", len(signature) == 64, "len=%d" % len(signature))

    candidates = {
        "plain Ed25519 over the input": ref25519.ed25519_sign(EDDSA_SEED, MESSAGE),
        "Ed25519 over SHA-512(input)": ref25519.ed25519_sign(
            EDDSA_SEED, hashlib.sha512(MESSAGE).digest()
        ),
        "Ed25519ph over SHA-512(input)": ref25519.ed25519ph_sign(
            EDDSA_SEED, hashlib.sha512(MESSAGE).digest()
        ),
    }
    match = [name for name, value in candidates.items() if value == signature]
    if match:
        report.check("signature matches " + match[0], True)
        report.info("card signature " + signature.hex().upper())
    else:
        report.check(
            "signature matches a known Ed25519 variant",
            False,
            "card produced " + signature.hex().upper(),
        )

    # Verify uses the same input convention as sign, so a positive and a negative case are both
    # meaningful even before the exact variant is known.
    data, sw = runner.send(apdu(INS_VERIFY, data=MESSAGE + signature))
    report.timing("verify (EdDSA)", runner.last_ms)
    expect(report, "verify accepts hash||signature", data, sw, b"", 0x9000)

    tampered = bytearray(signature)
    tampered[10] ^= 0x01
    data, sw = runner.send(apdu(INS_VERIFY, data=MESSAGE + bytes(tampered)))
    report.check("verify rejects a modified signature", sw == 0x6982, "SW=%04X" % sw)

    # --- X25519 -------------------------------------------------------------------------------
    # The reconstructed library reverses the byte order of X25519 *public* keys, but passes the
    # private scalar through unchanged. JCOPX itself works big endian internally, so a scalar that
    # the caller wants in RFC 7748 (little endian) order has to be reversed before import.
    data, sw = runner.send(apdu(INS_SET_PRIVATE, P1_X25519, data=X25519_SCALAR[::-1]))
    expect(report, "import X25519 scalar (big endian)", data, sw, b"")

    data, sw = runner.send(apdu(INS_SET_PUBLIC, P1_X25519, data=X25519_PUBLIC))
    expect(report, "import X25519 public key", data, sw, b"")

    data, sw = runner.send(apdu(INS_GET_PUBLIC, P1_X25519))
    expect(report, "read back X25519 public key", data, sw, X25519_PUBLIC)

    data, sw = runner.send(apdu(INS_EXCHANGE, data=X25519_PEER_PUBLIC))
    report.timing("X25519 exchange", runner.last_ms)
    expect(report, "X25519 shared secret", data, sw, X25519_SHARED)

    data, sw = runner.send(apdu(INS_INFO))
    if sw == 0x9000 and len(data) == 12:
        report.info(
            "sizes=%d/%d/%d/%d initialised=%s"
            % (data[4], data[5], data[6], data[7], ",".join(str(b) for b in data[8:12]))
        )
        report.info("keys initialised: " + ",".join(str(b) for b in data[8:12]))
    else:
        report.check("info after import", False, "SW=%04X len=%d" % (sw, len(data)))

    # --- key generation -----------------------------------------------------------------------
    data, sw = runner.send(apdu(INS_GENERATE_PAIR, P1_EDDSA))
    report.timing("genKeyPair (EdDSA)", runner.last_ms)
    generated_public = data
    if expect(report, "generate EdDSA key pair", data, sw, None) and len(generated_public) == 32:
        data, sw = runner.send(apdu(INS_GET_PRIVATE, P1_EDDSA))
        generated_seed = data
        if expect(report, "read generated EdDSA seed", data, sw, None) and len(generated_seed) == 32:
            report.check(
                "generated EdDSA public key matches its seed",
                ref25519.ed25519_public_key(generated_seed) == generated_public,
                generated_public.hex().upper(),
            )

    data, sw = runner.send(apdu(INS_GENERATE_PAIR, P1_X25519))
    report.timing("genKeyPair (X25519)", runner.last_ms)
    generated_public = data
    if expect(report, "generate X25519 key pair", data, sw, None) and len(generated_public) == 32:
        data, sw = runner.send(apdu(INS_GET_PRIVATE, P1_X25519))
        generated_scalar = data
        if expect(report, "read generated X25519 scalar", data, sw, None) and len(generated_scalar) == 32:
            report.check(
                "generated X25519 public key matches its scalar",
                ref25519.x25519_public_key(generated_scalar[::-1]) == generated_public,
                generated_public.hex().upper(),
            )

    # --- error paths --------------------------------------------------------------------------
    data, sw = runner.send(apdu(INS_SET_PUBLIC, P1_EDDSA, data=b"\x00" * 16))
    report.check("setW rejects a 16 byte key", sw == 0x6700, "SW=%04X" % sw)

    data, sw = runner.send(apdu(INS_VERIFY, data=MESSAGE + signature[:32]))
    report.check("verify rejects a short signature", sw == 0x6700, "SW=%04X" % sw)


def self_check():
    report = Report()
    report.check("Ed25519 public key", ref25519.ed25519_public_key(EDDSA_SEED) == EDDSA_PUBLIC)
    report.check(
        "Ed25519 signature",
        ref25519.ed25519_verify(
            EDDSA_PUBLIC, MESSAGE, ref25519.ed25519_sign(EDDSA_SEED, MESSAGE)
        ),
    )
    report.check("X25519 public key", ref25519.x25519_public_key(X25519_SCALAR) == X25519_PUBLIC)
    report.check(
        "X25519 shared secret",
        ref25519.x25519(X25519_SCALAR, X25519_PEER_PUBLIC) == X25519_SHARED,
    )
    return report.summary()


def ensure_runner(directory):
    directory = fs_path(directory)
    os.makedirs(directory, exist_ok=True)
    target = os.path.join(directory, "ApduRunner.java")
    shutil.copyfile(APDU_RUNNER_SOURCE, target)
    javac = os.path.join(WINDOWS_JDK, "javac.exe")
    result = subprocess.run(
        [javac, "-d", ".", "ApduRunner.java"],
        cwd=directory,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if result.returncode != 0:
        print(result.stdout, file=sys.stderr)
        raise SystemExit("error: could not compile ApduRunner")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--aid", default=DEFAULT_AID)
    parser.add_argument(
        "--dir",
        default=os.environ.get("CARD_RUNNER_DIR", DEFAULT_DIR),
        help="Windows directory for ApduRunner, or a WSL path when CARD_RUNNER_DIR is set",
    )
    parser.add_argument("--self-check", action="store_true")
    parser.add_argument(
        "--timing", action="store_true", help="report per-operation timings on the card"
    )
    args = parser.parse_args(argv)

    if not self_check():
        return 1
    if args.self_check:
        return 0

    report = Report(show_timing=args.timing)
    ensure_runner(args.dir)
    try:
        runner = Runner(args.aid, args.dir)
    except Exception as error:
        print("error: could not start ApduRunner: %s" % error, file=sys.stderr)
        return 1

    if "selected" not in runner.select_line:
        print("error: applet not selected, see the ApduRunner output below", file=sys.stderr)
        print(runner.process.stderr.read(), file=sys.stderr)
        return 1

    try:
        run_card_tests(runner, report)
    finally:
        runner.close()

    return 0 if report.summary() else 1


if __name__ == "__main__":
    sys.exit(main())
