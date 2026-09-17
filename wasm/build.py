"""Build the npm package aamio-wasm from the Rust core.

    python wasm/build.py        # wasm/pkg/, ready for `npm publish`
    node wasm/test/check.mjs    # the shared vectors, through the built package
    node wasm/test/bench.mjs    # proof of work: this against aamio-js, same inputs

Needs cargo with the wasm32-unknown-unknown target, and the wasm-bindgen CLI
in the same version as the wasm-bindgen crate in wasm/Cargo.lock, on PATH or
named by WASM_BINDGEN. CARGO_TARGET_DIR is respected.
"""

import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(HERE, "pkg")
TARGET = os.environ.get("CARGO_TARGET_DIR") or os.path.join(HERE, "target")
BINDGEN = os.environ.get("WASM_BINDGEN") or "wasm-bindgen"


def run(*cmd, cwd=HERE):
    print("+ " + " ".join(os.path.basename(c) if i == 0 else c for i, c in enumerate(cmd)))
    subprocess.run(cmd, check=True, cwd=cwd)


def main():
    run("cargo", "build", "--release", "--target", "wasm32-unknown-unknown")
    wasm = os.path.join(TARGET, "wasm32-unknown-unknown", "release", "aamio_wasm.wasm")
    shutil.rmtree(PKG, ignore_errors=True)
    os.makedirs(PKG)
    run(BINDGEN, "--target", "web", "--out-dir", os.path.join(PKG, "web"), wasm)
    for name in ("index.js", "index.d.ts", "package.json"):
        shutil.copyfile(os.path.join(HERE, "js", name), os.path.join(PKG, name))
    shutil.copyfile(os.path.join(HERE, "README.md"), os.path.join(PKG, "README.md"))
    licence = os.path.join(HERE, "..", "LICENSE")
    if os.path.exists(licence):
        shutil.copyfile(licence, os.path.join(PKG, "LICENSE"))
    size = os.path.getsize(os.path.join(PKG, "web", "aamio_wasm_bg.wasm"))
    print("pkg: wasm/pkg, aamio_wasm_bg.wasm is %d bytes" % size)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
