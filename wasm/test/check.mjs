// The shared vectors, through the built npm package. Nothing touches the network.
//
//   python wasm/build.py && node wasm/test/check.mjs

import { readFile } from "node:fs/promises";
import * as aamio from "../pkg/index.js";

const v = JSON.parse(await readFile(new URL("../../testdata/vectors.json", import.meta.url), "utf8"));

let passed = 0;
let failed = 0;
const ok = (condition, label) => {
  condition ? passed++ : failed++;
  console.log((condition ? "  ok    " : "  FAIL  ") + label);
};
const throws = (fn, needle) => {
  try {
    fn();
  } catch (error) {
    return needle === undefined || String(error.message).includes(needle);
  }
  return false;
};
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const unhex = (text) => new Uint8Array(Buffer.from(text, "hex"));
const utf8 = (text) => new TextEncoder().encode(text);
const unb64url = (text) => new Uint8Array(Buffer.from(text, "base64url"));

const seedA = unhex(v.a.seed);
const seedB = unhex(v.b.seed);

console.log("keys and signing");
ok(aamio.publicKey(seedA) === v.a.public && aamio.publicKey(seedB) === v.b.public, "public keys from seeds");
ok(aamio.sign(seedA, v.signInput) === v.signature, "signature of A over the vector input, byte for byte");
ok(aamio.verify(v.a.public, v.signature, v.signInput) && !aamio.verify(v.b.public, v.signature, v.signInput) && !aamio.verify(v.a.public, v.signature, v.signInput + "x"), "verify");
ok(throws(() => aamio.publicKey(new Uint8Array(31)), "32 bytes"), "a seed of the wrong length is refused");
const fresh = aamio.generateSeed();
ok(fresh.length === 32 && hex(fresh) !== hex(aamio.generateSeed()) && aamio.publicKey(fresh).length === 43, "a fresh seed comes from crypto.getRandomValues, and is a key");

console.log("sealing");
ok(new TextDecoder().decode(aamio.open(seedB, v.a.public, v.envelopeFromAToB)) === v.plaintext, "B opens the envelope A sealed, made by PyNaCl");
const nonce = unb64url(JSON.parse(v.envelopeFromAToB).nonce);
ok(aamio.sealWithNonce(seedA, v.b.public, utf8(v.plaintext), nonce) === v.envelopeFromAToB, "the same keys, plaintext and nonce give PyNaCl's envelope byte for byte");
const sealed = aamio.seal(seedA, v.b.public, utf8("fra wasm til hvem som helst"));
ok(sealed !== aamio.seal(seedA, v.b.public, utf8("fra wasm til hvem som helst")) && JSON.parse(sealed).e2ee === "nacl.box.v1", "a fresh nonce every time");
ok(new TextDecoder().decode(aamio.open(seedB, v.a.public, sealed)) === "fra wasm til hvem som helst", "B opens what A sealed here");
ok(throws(() => aamio.open(seedA, v.b.public, sealed), "sealed to"), "A cannot open an envelope sealed to B, and is told whom it was sealed to");
ok(throws(() => aamio.open(seedB, aamio.publicKey(fresh), sealed)), "it does not open with the wrong sender key");
ok(throws(() => aamio.sealWithNonce(seedA, v.b.public, utf8("x"), new Uint8Array(23)), "24 bytes"), "a nonce of the wrong length is refused");

console.log("gate");
ok(aamio.canonicalGate('{"advise":{"pow":{"covers":1,"bits":16}},"require":{}}') === '{"advise":{"pow":{"bits":16,"covers":1}}}', "keys sorted, empty bucket removed");
ok(aamio.gateHash('{"advise":{"pow":{"covers":1,"bits":16}},"require":{}}') === "de2a8fd4c8d7cbf9f6839c810632caf2c4b40fd8ba99ad19678f6c5b063d4d64", "published gate_hash");
ok(aamio.canonicalGate('{"require":{},"advise":{}}') === "{}" && aamio.gateHash('{"require":{},"advise":{}}') === "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "an empty gate is {} and hashes to the published value");
const points = [0x61, 0x22, 0x62, 0x5c, 0x63, 0x2f, 0x64, 0x01, 0x65, 0x1f, 0x66, 0x0a, 0x67, 0xe6, 0x68, 0x2028, 0x69, 0x1f600, 0x6a, 0x7f];
const canonical = aamio.canonicalGate(JSON.stringify({ s: String.fromCodePoint(...points) }));
ok(hex(utf8(canonical)) === "7b2273223a22615c22625c5c632f645c7530303031655c7530303166665c6e67c3a668e280a869f09f98806a7f227d", "string escaping, byte for byte");
ok(throws(() => aamio.canonicalGate("[1]"), "JSON object") && throws(() => aamio.canonicalGate("nope"), "JSON object"), "a gate that is not an object is refused");

console.log("proof of work");
const w = "b4netymg7r5nnt2yiscp";
const key = "A".repeat(43);
const sha = "36751f20147f74e3dfbaf829fb8f04ea9ed596268bd685a69fdfa5992fddd6b8";
const signed = aamio.powDigest(w, key, sha, "7036");
ok(hex(signed) === "00003a2ac769f2265d621969d9ff1feaaa2b9dcc6f006b6adae1d22c2db8a842" && aamio.zeroBits(signed) === 18, "signed: nonce 7036 gives 18 bits");
const unsigned = aamio.powDigest(w, "", sha, "91617");
ok(hex(unsigned) === "000018b5cc286cf27d2c97296aff9e2e60db0c165e7cf3af7a44857423c08612" && aamio.zeroBits(unsigned) === 19, "unsigned: nonce 91617 gives 19 bits");
let slow = 0;
while (aamio.zeroBits(aamio.powDigest(w, key, sha, String(slow))) < 12) slow++;
ok(aamio.solvePow(w, key, sha, 12) === String(slow), "solvePow finds the first nonce, the one counting from 0 one hash at a time finds: " + slow);
let slowBoard = 0;
while (aamio.zeroBits(aamio.boardPowDigest(key, sha, String(slowBoard))) < 12) slowBoard++;
ok(aamio.solveBoardPow(key, sha, 12) === String(slowBoard), "solveBoardPow does too: " + slowBoard);
ok(aamio.solvePow(w, key, sha, 0) === "0", "no bits asked is the first nonce");
ok(throws(() => aamio.solvePow(w, key, sha, 21), "0 to 20"), "above the ceiling is refused, not attempted");
ok(/^\d+\.\d+\.\d+$/.test(aamio.version()), "version " + aamio.version());

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed === 0 ? 0 : 1);
