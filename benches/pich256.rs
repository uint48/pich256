//! Criterion benchmarks for Pich256.
//!
//!     cargo bench                      # everything
//!     cargo bench -- encrypt           # one group
//!     cargo bench -- --save-baseline a # record a baseline to compare against
//!     cargo bench -- --baseline a      # compare the current run to it
//!
//! Every group that touches the cipher is parameterised over
//! [`arch::supported_backends`], so a single run reports each code path the host
//! CPU can execute next to the portable reference. The backend is process-global
//! state, so it is pinned immediately before each `bench_function` call - which
//! Criterion runs synchronously - and reset once the group is done.
//!
//! For a quick human-readable summary instead of a statistical one, see
//! `examples/arch_bench.rs`.

use std::hint::black_box;
use std::time::Duration;

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use pich256::arch::{self, Backend};
use pich256::pich256::Pich256;

/// A 16-entry round-key schedule shaped like the one `gen_sub_keys` produces,
/// for the primitive benchmarks that bypass `Pich256`.
fn sample_schedule() -> Vec<u128> {
    (0..16u128)
        .map(|i| {
            i.wrapping_mul(0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835) ^ (i << 100)
        })
        .collect()
}

/// Deterministic filler, so every run benchmarks identical bytes.
fn pattern(len: usize) -> Vec<u8> {
    let mut s = 0x2545_F491_4F6C_DD1Du64;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

// ==============================================================================
// End-to-end
// ==============================================================================

/// Cost of `Pich256::new`: two HMAC-SHA256 passes, 16 subkeys, 62 warm-up rounds.
///
/// This is a fixed cost paid before a single plaintext byte is touched, so it
/// dominates short messages and is worth tracking separately from throughput.
fn key_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_setup");

    for &backend in &arch::supported_backends() {
        arch::force_backend(backend);
        group.bench_function(backend.name(), |b| {
            b.iter(|| Pich256::new(black_box("correct horse battery staple")));
        });
    }
    arch::reset_backend();

    group.finish();
}

/// Encryption throughput, including the output allocation.
///
/// The cipher instance is reused across iterations: its state advances, but the
/// per-byte cost does not, and this keeps the fixed key-setup cost measured by
/// `key_setup` out of the throughput figure.
fn encrypt(c: &mut Criterion) {
    let mut group = c.benchmark_group("encrypt");

    for &size in &[64usize, 1024, 65536] {
        let msg = pattern(size);
        group.throughput(Throughput::Bytes(size as u64));

        for &backend in &arch::supported_backends() {
            arch::force_backend(backend);
            group.bench_with_input(
                BenchmarkId::new(backend.name(), size),
                &msg,
                |b, msg| {
                    let mut cipher = Pich256::new("benchmark key");
                    b.iter(|| black_box(cipher.encrypt(black_box(msg))));
                },
            );
        }
        arch::reset_backend();
    }

    group.finish();
}

// ==============================================================================
// Cipher primitives
// ==============================================================================

/// Keystream generation on its own - the cipher's real cost centre, with no
/// allocation and no plaintext XOR.
fn keystream(c: &mut Criterion) {
    let mut group = c.benchmark_group("keystream");
    const LEN: usize = 4096;
    group.throughput(Throughput::Bytes(LEN as u64));

    let schedule = sample_schedule();

    for &backend in &arch::supported_backends() {
        arch::force_backend(backend);
        group.bench_function(backend.name(), |b| {
            let mut out = vec![0u8; LEN];
            let mut w = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
            let mut round_index = 0usize;
            b.iter(|| {
                arch::fill_keystream(
                    black_box(&mut w),
                    black_box(&schedule),
                    black_box(&mut round_index),
                    black_box(&mut out),
                )
            });
        });
    }
    arch::reset_backend();

    group.finish();
}

/// The AES S-box over a bulk buffer: the widest each backend can go.
fn sub_bytes(c: &mut Criterion) {
    let mut group = c.benchmark_group("sub_bytes");
    const LEN: usize = 4096;
    group.throughput(Throughput::Bytes(LEN as u64));

    for &backend in &arch::supported_backends() {
        arch::force_backend(backend);
        group.bench_function(backend.name(), |b| {
            let mut buf = pattern(LEN);
            b.iter(|| arch::sub_bytes(black_box(&mut buf)));
        });
    }
    arch::reset_backend();

    group.finish();
}

/// A single dispatched round.
///
/// Note this pays a non-inlinable call into the backend on every iteration,
/// which the real keystream loop does not - see `arch::fill_keystream`. Read it
/// as a latency comparison between backends, not as the cipher's per-round cost;
/// the `keystream` group is the honest one.
fn round(c: &mut Criterion) {
    let mut group = c.benchmark_group("round128");

    for &backend in &arch::supported_backends() {
        arch::force_backend(backend);
        group.bench_function(backend.name(), |b| {
            let mut w = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
            let key = 0xA5A5_5A5A_C3C3_3C3C_0F0F_F0F0_1234_5678u128;
            b.iter(|| {
                w = arch::round128(black_box(w), black_box(key));
                w
            });
        });
    }
    arch::reset_backend();

    group.finish();
}

/// Bulk `dst ^= src`, the second half of `encrypt`.
fn xor_into(c: &mut Criterion) {
    let mut group = c.benchmark_group("xor_into");
    const LEN: usize = 65536;
    group.throughput(Throughput::Bytes(LEN as u64));

    let src = pattern(LEN);

    group.bench_function("dispatched", |b| {
        let mut dst = pattern(LEN);
        b.iter(|| arch::xor_into(black_box(&mut dst), black_box(&src)));
    });
    group.bench_function("portable", |b| {
        let mut dst = pattern(LEN);
        b.iter(|| arch::fallback::xor_into(black_box(&mut dst), black_box(&src)));
    });

    group.finish();
}

// ==============================================================================
// Hash and integer primitives
// ==============================================================================

/// SHA-256 block compression: SHA-NI against the portable loop.
///
/// Not parameterised by `Backend` - the SHA extensions are an independent CPUID
/// bit, so the comparison is the dispatched path against `fallback` directly.
fn sha256_compress(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256_compress");
    const BLOCKS: usize = 16;
    let data = pattern(BLOCKS * 64);
    group.throughput(Throughput::Bytes(data.len() as u64));

    const IV: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
        0x5be0cd19,
    ];

    let label = if arch::has_sha_ni() { "sha-ni" } else { "portable (no sha-ni)" };
    group.bench_function(label, |b| {
        let mut state = IV;
        b.iter(|| arch::sha256_compress(black_box(&mut state), black_box(&data)));
    });
    group.bench_function("portable", |b| {
        let mut state = IV;
        b.iter(|| arch::fallback::sha256_compress(black_box(&mut state), black_box(&data)));
    });

    group.finish();
}

/// The 128-bit integer primitives behind the subkey generator `g`: inline
/// assembly against the equivalent plain Rust.
fn int_primitives(c: &mut Criterion) {
    let mut group = c.benchmark_group("int128");

    group.bench_function("rotr128/dispatched", |b| {
        let mut x = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
        b.iter(|| {
            x = arch::rotr128(black_box(x), black_box(7));
            x
        });
    });
    group.bench_function("rotr128/portable", |b| {
        let mut x = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
        b.iter(|| {
            x = arch::fallback::rotr128(black_box(x), black_box(7));
            x
        });
    });
    group.bench_function("mul128/dispatched", |b| {
        let mut x = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
        b.iter(|| {
            x = arch::mul128(black_box(x), black_box(0x9E37_79B9_7F4A_7C15u128));
            x
        });
    });
    group.bench_function("mul128/portable", |b| {
        let mut x = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
        b.iter(|| {
            x = arch::fallback::mul128(black_box(x), black_box(0x9E37_79B9_7F4A_7C15u128));
            x
        });
    });

    group.finish();
}

// ==============================================================================

/// Guards against the benchmarks silently measuring the wrong thing: if a
/// backend ever stopped agreeing with the portable reference, the numbers below
/// it would be meaningless.
fn assert_backends_agree() {
    let msg = pattern(1024);

    arch::force_backend(Backend::Fallback);
    let reference = Pich256::new("bench-consistency").encrypt(&msg);

    for backend in arch::supported_backends() {
        arch::force_backend(backend);
        let actual = Pich256::new("bench-consistency").encrypt(&msg);
        assert_eq!(
            actual,
            reference,
            "backend {} disagrees with the portable reference; benchmark results \
             would be comparing different computations",
            backend.name()
        );
    }
    arch::reset_backend();
}

fn all(c: &mut Criterion) {
    assert_backends_agree();

    println!("host: {}", arch::cpu_summary());
    println!("detected backend: {}", arch::backend().name());

    key_setup(c);
    encrypt(c);
    keystream(c);
    sub_bytes(c);
    round(c);
    xor_into(c);
    sha256_compress(c);
    int_primitives(c);
}

criterion_group! {
    name = benches;
    // Trimmed from Criterion's defaults so a full sweep over every backend stays
    // in the tens of seconds rather than the tens of minutes.
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .sample_size(50);
    targets = all
}
criterion_main!(benches);
