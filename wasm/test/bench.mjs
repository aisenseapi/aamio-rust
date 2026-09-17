// Proof of work: this package against aamio-js, the same inputs, one thread.
// Both must find the same nonce, or the comparison means nothing.
//
//   node wasm/test/bench.mjs [path to aamio-js/src/aamio.js]
//
// Numbers from one machine are numbers from one machine. What carries over is
// the ratio, and that the whole search is one call into WebAssembly.

import { performance } from "node:perf_hooks";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
import { solvePow } from "../pkg/index.js";

const jsPath = process.argv[2] || new URL("../../../aamio-js/src/aamio.js", import.meta.url).href;
const { solveWork, sha256hex } = await import(jsPath.startsWith("file:") ? jsPath : pathToFileURL(resolve(jsPath)).href);

const w = "b4netymg7r5nnt2yiscp";
const key = "A".repeat(43);
const rows = [];

for (const [bits, rounds] of [[12, 20], [16, 12], [18, 8], [20, 4]]) {
  let js = 0;
  let wasm = 0;
  let tries = 0;
  for (let i = 0; i < rounds; i++) {
    const body = JSON.stringify({ text: "benchmark", bits, i });
    const sha = sha256hex(body);
    let t = performance.now();
    const fromJs = solveWork(w, key, body, bits);
    js += performance.now() - t;
    t = performance.now();
    const fromWasm = solvePow(w, key, sha, bits);
    wasm += performance.now() - t;
    if (fromJs !== fromWasm) throw new Error(`different nonces at ${bits} bits: ${fromJs} and ${fromWasm}`);
    tries += Number(fromJs) + 1;
  }
  rows.push({ bits, rounds, tries: Math.round(tries / rounds), js: js / rounds, wasm: wasm / rounds });
}

console.log("bits  rounds  mean tries   aamio-js      aamio-wasm    ratio");
for (const r of rows) {
  console.log(
    String(r.bits).padEnd(6) + String(r.rounds).padEnd(8) + String(r.tries).padEnd(13) +
    (r.js.toFixed(1) + " ms").padEnd(14) + (r.wasm.toFixed(1) + " ms").padEnd(14) + (r.js / r.wasm).toFixed(1) + "x",
  );
}
