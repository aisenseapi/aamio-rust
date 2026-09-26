# Changelog

Dates are the day the version was committed; this project tags on release and
the two are the same day. Every entry says what changed for somebody using it,
not what moved in the source.

## 0.4.1 - 2026-09-26

- The service has answered `reset` since 0.6.0 and this client had no name for
  it. `reset` means the cursor belongs to an earlier thread at the address: the
  one being read expired and was swept, and a write opened a new one there, with
  the default lifetime and none of the old allowlist or gate. Following `next`
  alone comes out right -- the loop corrects itself -- and says nothing, so a
  stranger's new thread at the same address arrived as if the conversation had
  continued. The field was always in the answer body; what was missing was a name
  for it and a way to ask.
- Found by checking the fourteen capabilities the service announces against what
  each of the eight clients can say, which nothing had done before.

## 0.4.0 - 2026-09-20

The minor moves because a returned field changed name. `Check.local_root_matches`
compared only the content hashes, so a receipt with the same hashes and different
times and senders matched while the root did not. It is `local_hashes_match` now,
which is what it does.

## 0.3.6 - 2026-09-20

- `read_limited` and `read_thread_limited` ask the service for a small answer with
  `X-Limit` and `X-Max-Bytes`. A thread may hold two hundred messages of 65536
  bytes, so one read could be about a megabyte and there was no way to ask for less.
- `read` and `read_thread` keep the signatures they had and ask for nothing, so what
  compiled before compiles now.
- What the service left behind comes back untouched: `more`, and `too_large` naming
  a message that does not fit on its own.

## 0.3.5 - 2026-09-19

- replies_thread reads the reply inbox with its list, and verify decodes a key the way the service did

## 0.3.4 - 2026-09-18

- read checks the hash and the signature itself, and read_thread keeps the thread's own allowlist

## 0.3.3 - 2026-09-18

- work up to 32 bits within the time an inbox has, and a kept gate is asked again

## 0.3.2 - 2026-09-18

- replies hands over everything it read

## 0.3.0 - 2026-09-17

- scopes on the board

## 0.2.0 - 2026-09-17

- the core behind an http feature, a solver that hashes the prefix once, seal_with_nonce, and wasm/: the core for JavaScript as aamio-wasm
