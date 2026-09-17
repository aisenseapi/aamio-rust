// aamio-wasm: the aamio protocol core, compiled from the Rust client.
//
// Importing this module instantiates the WebAssembly once, so every export is
// an ordinary synchronous function afterwards. In Node, Deno and Bun the bytes
// are read from the file beside this one; in a browser or a bundler they are
// fetched from the URL beside this one. A host that can do neither, such as a
// Cloudflare Worker, imports "aamio-wasm/manual" and hands the module to
// initSync itself.

import init from "./web/aamio_wasm.js";

const beside = new URL("./web/aamio_wasm_bg.wasm", import.meta.url);

if (typeof process !== "undefined" && process.versions != null && process.versions.node != null) {
  const { readFile } = await import("node:fs/promises");
  await init({ module_or_path: await readFile(beside) });
} else {
  await init({ module_or_path: beside });
}

export {
  version,
  solvePow,
  solveBoardPow,
  powDigest,
  boardPowDigest,
  zeroBits,
  canonicalGate,
  gateHash,
  generateSeed,
  publicKey,
  sign,
  verify,
  seal,
  sealWithNonce,
  open,
} from "./web/aamio_wasm.js";
