//! Reports which architecture backend this machine selected and measures the
//! accelerated primitives against the portable reference implementation.
//!
//!     cargo run --release --example arch_bench
//!     cargo run --release --example arch_bench --no-default-features
//!
//! The second form forces every call through `arch::fallback`, so the two runs
//! together show what the hardware paths are actually worth on this CPU.

use std::hint::black_box;
use std::time::Instant;

use pich256::arch;
use pich256::pich256::Pich256;

/// Runs `f` enough times to get a stable reading and returns nanoseconds per
/// processed byte.
fn ns_per_byte(bytes_per_call: usize, calls: usize, mut f: impl FnMut()) -> f64 {
    // Warm up: first call pays for CPU detection, page faults and frequency ramp.
    for _ in 0..calls / 10 + 1 {
        f();
    }
    let start = Instant::now();
    for _ in 0..calls {
        f();
    }
    let elapsed = start.elapsed();
    elapsed.as_nanos() as f64 / (bytes_per_call * calls) as f64
}

fn banner(title: &str) {
    println!("\n{title}");
    println!("{}", "-".repeat(title.len()));
}

fn main() {
    banner("host");
    println!("  cpu      : {}", arch::cpu_summary());
    println!("  backend  : {}", arch::backend().name());
    println!("  sha-ni   : {}", arch::has_sha_ni());
    println!(
        "  features : simd={} asm={}",
        cfg!(feature = "simd"),
        cfg!(feature = "asm")
    );

    let detected = arch::backend();
    let backends = arch::supported_backends();

    // ---- S-box substitution ------------------------------------------------
    banner("sub_bytes (AES S-box over a 64 KiB buffer)");
    let mut buf = vec![0u8; 64 * 1024];
    for (i, b) in buf.iter_mut().enumerate() {
        *b = i as u8;
    }

    for &b in &backends {
        arch::force_backend(b);
        let t = ns_per_byte(buf.len(), 200, || {
            arch::sub_bytes(black_box(&mut buf));
        });
        println!("  {:<18} {:>7.3} ns/byte   {:>7.2} GiB/s", b.name(), t, 1.0 / t);
    }
    arch::reset_backend();

    // ---- the fused cipher round -------------------------------------------
    banner("round128 (rotate + S-box + key XOR)");
    for &b in &backends {
        arch::force_backend(b);
        let mut w = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
        let k = 0xA5A5_5A5A_C3C3_3C3C_0F0F_F0F0_1234_5678u128;
        let iters = 2_000_000usize;
        let start = Instant::now();
        for _ in 0..iters {
            w = arch::round128(black_box(w), black_box(k));
        }
        let ns = start.elapsed().as_nanos() as f64 / iters as f64;
        black_box(w);
        println!("  {:<18} {:>7.3} ns/round", b.name(), ns);
    }
    arch::reset_backend();

    // ---- SHA-256 compression (the KDF's inner loop) ------------------------
    banner("sha256_compress (1 MiB of blocks)");
    {
        let blocks = vec![0x5Au8; 1024 * 1024];
        let mut state = [
            0x6a09e667u32, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let t = ns_per_byte(blocks.len(), 20, || {
            arch::sha256_compress(black_box(&mut state), black_box(&blocks));
        });
        let label = if arch::has_sha_ni() { "x86_64/sha-ni" } else { "portable" };
        println!("  {:<18} {:>7.3} ns/byte   {:>7.2} GiB/s", label, t, 1.0 / t);

        // And the portable path, for comparison, whatever the CPU supports.
        let mut state2 = state;
        let t2 = ns_per_byte(blocks.len(), 20, || {
            pich256::arch::fallback::sha256_compress(black_box(&mut state2), black_box(&blocks));
        });
        println!("  {:<18} {:>7.3} ns/byte   {:>7.2} GiB/s", "portable", t2, 1.0 / t2);
    }

    // ---- end-to-end encryption --------------------------------------------
    banner("Pich256::encrypt (end to end)");
    let msg = vec![0x42u8; 32 * 1024];
    for &b in &backends {
        arch::force_backend(b);
        let t = ns_per_byte(msg.len(), 20, || {
            let mut c = Pich256::new("benchmark key");
            black_box(c.encrypt(black_box(&msg)));
        });
        println!("  {:<18} {:>7.3} ns/byte   {:>7.2} MiB/s", b.name(), t, 1000.0 / t);
    }
    arch::reset_backend();

    // ---- sanity: every backend must agree ---------------------------------
    banner("equivalence check");
    let plaintext = b"the backends must be bit-for-bit identical";

    arch::force_backend(arch::Backend::Fallback);
    let portable = Pich256::new("equivalence").encrypt(plaintext);
    arch::reset_backend();

    for &b in &backends {
        arch::force_backend(b);
        let actual = Pich256::new("equivalence").encrypt(plaintext);
        println!(
            "  {:<18} {}",
            b.name(),
            if actual == portable { "identical" } else { "MISMATCH" }
        );
        assert_eq!(actual, portable, "{} produced different ciphertext", b.name());
    }
    arch::reset_backend();
    let _ = detected;
}
