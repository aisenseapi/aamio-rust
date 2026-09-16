"""Rust and Python as one client: what one seals the other opens, what one signs the other verifies.

Run from aamio-rust with the aamio-python checkout beside it and cargo on
PATH, or AAMIO_CARGO pointing at the cargo binary:

    python tests/interop.py

Nothing touches the network. Python is the reference because its box is
PyNaCl's, which the shared vectors were made with; Rust is the port under test.
"""

import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..")
sys.path.insert(0, os.path.join(ROOT, "..", "aamio-python", "src"))

from nacl.signing import SigningKey, VerifyKey  # noqa: E402
from aamio.crypto import Keys, b64url, thread_signing_input, unb64url  # noqa: E402

CARGO = os.environ.get("AAMIO_CARGO", "cargo")


def main():
    py = Keys(os.urandom(32))
    rust_seed = os.urandom(32)
    rust_public = b64url(bytes(SigningKey(rust_seed).verify_key))
    signing_input = thread_signing_input("ohcibx4t22xc6hx22fch", '{"hello":"from python"}')
    request = {
        "rust_seed": rust_seed.hex(),
        "py_public": py.public,
        "signing_input": signing_input,
        "py_signature": py.sign(signing_input),
        "plaintext_for_py": "fra rust, åpnet i python 🦀",
        "envelope_from_py": py.seal(rust_public, "fra python, åpnet i rust 🐍".encode("utf-8")),
    }
    run = subprocess.run([CARGO, "run", "--quiet", "--example", "interop"], cwd=ROOT, input=json.dumps(request).encode("utf-8"), capture_output=True, check=True)
    out = json.loads(run.stdout.decode("utf-8"))

    checks = [
        (out["rust_public"] == rust_public, "Rust derives the same public key from the seed as PyNaCl"),
        (out["opened"] == "fra python, åpnet i rust 🐍", "Rust opens what Python sealed to it"),
        (out["py_signature_verifies"] is True, "Rust verifies Python's signature"),
        (py.open(rust_public, out["envelope_from_rust"]).decode("utf-8") == request["plaintext_for_py"], "Python opens what Rust sealed to it"),
    ]
    try:
        VerifyKey(unb64url(rust_public)).verify(signing_input.encode("utf-8"), unb64url(out["rust_signature"]))
        checks.append((True, "Python verifies Rust's signature"))
    except Exception:
        checks.append((False, "Python verifies Rust's signature"))

    failed = 0
    for ok, label in checks:
        print(("  ok    " if ok else "  FAIL  ") + label)
        failed += 0 if ok else 1
    print("\n%d passed, %d failed" % (len(checks) - failed, failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
