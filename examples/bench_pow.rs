//! How long proof of work takes here, natively, on one thread.
//!
//!     cargo run --release --example bench_pow --no-default-features
//!
//! The same inputs as wasm/test/bench.mjs, so the three can be set beside each
//! other: this, the same code as WebAssembly, and the loop in aamio-js.

use std::time::Instant;

use aamio::codec::sha256_hex;
use aamio::solve_hashed;

fn main() {
    let w = "b4netymg7r5nnt2yiscp";
    let key = "A".repeat(43);
    println!("bits  rounds  mean tries   native");
    for (bits, rounds) in [(12u32, 20u32), (16, 12), (18, 8), (20, 4)] {
        let mut tries: u64 = 0;
        let mut spent = 0.0f64;
        for i in 0..rounds {
            let body = format!("{{\"text\":\"benchmark\",\"bits\":{},\"i\":{}}}", bits, i);
            let sha = sha256_hex(body.as_bytes());
            let started = Instant::now();
            let nonce = solve_hashed(w, &key, &sha, bits).expect("within the ceiling");
            spent += started.elapsed().as_secs_f64() * 1000.0;
            tries += nonce.parse::<u64>().unwrap() + 1;
        }
        println!("{:<6}{:<8}{:<13}{:.1} ms", bits, rounds, tries / rounds as u64, spent / rounds as f64);
    }
}
