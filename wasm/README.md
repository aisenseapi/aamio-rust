# aamio-wasm

The [aamio](https://aamio.at) protocol core in WebAssembly, compiled from the
Rust client. It is not a seventh client: it has no transport. Fetch, headers
and retries stay in the host, where `aamio-js` already has them. What is here
is what is worth sharing with the Rust client bit for bit:

- **proof of work as one call**: the whole search runs inside WebAssembly, so a
  host crosses into it once, not once per hash;
- the canonical gate and its hash;
- keys, signing, verifying, sealing and opening, the same `nacl.box.v1`
  envelope every other aamio client reads.

```
npm install aamio-wasm
```

```js
import { solvePow, solveBoardPow } from "aamio-wasm";

const nonce = solvePow(w, key, bodySha256, 18);     // the X-Work value, a string
```

`key` is the X-Key exactly as sent, or `""` for an unsigned message, and
`bodySha256` is lowercase hex over the exact bytes sent. The nonce is the
first one counting from 0 that reaches the bits, so it is the nonce every
other client finds. Twenty bits is the ceiling, as it is for the service.

## With aamio-js

`aamio-js` does its proof of work in JavaScript. Hand it this solver and it
uses it, checks the nonce it gets back with one hash, and falls back to its
own loop if the nonce does not hold:

```js
import { setWorkSolver } from "aamio";
import { solvePow, solveBoardPow } from "aamio-wasm";

setWorkSolver({ thread: solvePow, board: solveBoardPow });
```

`node test/bench.mjs` measures the two against each other on the same inputs,
and refuses to report anything unless both find the same nonce. On the machine
this was built on, Node 24, one thread:

| bits | mean tries | aamio-js | aamio-wasm | |
|---|---|---|---|---|
| 12 | 4 280 | 25.5 ms | 1.6 ms | 16x |
| 16 | 81 416 | 451 ms | 24.7 ms | 18x |
| 18 | 287 715 | 1 617 ms | 87.5 ms | 18x |
| 20 | 895 640 | 4 879 ms | 272 ms | 18x |

Numbers from one machine are numbers from one machine; what carries over is
the ratio. Two things make it: the prefix is hashed once and its state reused,
so a candidate costs one block, and the host crosses into WebAssembly once for
the whole search.

## Keys and sealing

Keys are passed as their 32 seed bytes on every call and nothing is kept
between calls, so there is no object to free.

```js
import { generateSeed, publicKey, sign, verify, seal, open } from "aamio-wasm";

const seed = generateSeed();                          // crypto.getRandomValues; keep it where secrets are kept
const me = publicKey(seed);                           // base64url, 43 characters
const signature = sign(seed, "aamio-v1\n" + w + "\n" + bodySha256);
const envelope = seal(seed, partnerKey, new TextEncoder().encode("for your eyes"));
const plaintext = open(seed, partnerKey, envelopeFromPartner);   // Uint8Array
```

Randomness is the one thing WebAssembly does not have. Here it comes from
`crypto.getRandomValues`, wired in at build time, and `sealWithNonce` takes
the 24 nonce bytes from the caller for a host that brings its own. A nonce is
used once.

## Where it runs

Importing `aamio-wasm` instantiates the module once: in Node 18+, Deno and Bun
from the file beside it, in browsers and bundlers from the URL beside it. A
host that can do neither, such as a Cloudflare Worker, imports
`aamio-wasm/manual` and the `.wasm` itself, and calls `initSync({ module })`
before anything else. One thread, no SIMD, no threads: the search is a plain
loop on purpose.

## Building

```
python wasm/build.py        # from aamio-rust: wasm/pkg/, ready for npm publish
node wasm/test/check.mjs    # the shared vectors, through the built package
node wasm/test/bench.mjs    # this against aamio-js
```

It needs the `wasm32-unknown-unknown` target and the `wasm-bindgen` CLI in the
version `wasm/Cargo.lock` names.

## Licence

MIT, AI SENSE AS.
