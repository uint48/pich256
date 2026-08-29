//! Architecture dispatch layer.
//!
//! Every performance-sensitive primitive in the crate is routed through this
//! module rather than being written inline at its call site. The call sites stay
//! architecture-neutral; this module decides, once per process, which
//! implementation to run.
//!
//! # How a backend gets chosen
//!
//! Selection happens at **runtime**, not at compile time. On x86_64 the host is
//! probed with `is_x86_feature_detected!` on first use and the answer is cached
//! in an atomic, so a single binary built anywhere runs everywhere: a machine
//! with AVX-512 takes the widest path, a 2008 machine takes the SSE2 path, and
//! nothing has to be recompiled with `-C target-cpu=native` to get the benefit.
//!
//! The alternative - compile-time `#[cfg(target_feature = ...)]` - was rejected
//! because it makes the default `cargo build` produce a baseline-SSE2 binary
//! while making a `target-cpu=native` binary crash with `SIGILL` if it is copied
//! to an older machine.
//!
//! # Adding an architecture
//!
//! [`fallback`] is the portable reference and always compiles. To add, say,
//! aarch64 NEON: add a `mod aarch64;` behind `#[cfg(target_arch = "aarch64")]`,
//! add its variants to [`Backend`], extend [`detect`], and add the arms to the
//! dispatch functions below. The unit tests at the bottom of this file already
//! check every *enabled* backend against [`fallback`], so a new backend is
//! covered as soon as it is wired up.
//!
//! # Cargo features
//!
//! * `simd` (default) - enables the vector backends. Turning it off routes every
//!   call to [`fallback`], which is useful for differential debugging.
//! * `asm` (default) - enables the inline-assembly integer primitives.

pub mod fallback;

#[cfg(all(any(feature = "simd", feature = "asm"), target_arch = "x86_64"))]
pub mod x86_64;

#[cfg(all(feature = "asm", target_arch = "x86_64"))]
use x86_64::int as asm_int;

use core::sync::atomic::{AtomicU8, Ordering};

// ==============================================================================
// Backend selection
// ==============================================================================

/// The implementation family selected for this process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Backend {
    /// Portable Rust; no CPU feature beyond the base target.
    Fallback = 0,
    /// x86_64 baseline: 128-bit vector loads/stores/XOR, scalar S-box.
    Sse2 = 1,
    /// `pshufb`-based constant-time S-box, 16 bytes per pass.
    Ssse3 = 2,
    /// `vpshufb`-based constant-time S-box, 32 bytes per pass.
    Avx2 = 3,
    /// `vpermi2b`-based constant-time S-box, 64 bytes per pass.
    Avx512Vbmi = 4,
    /// AES hardware: `pshufb` + `aesenclast` computes the S-box *and* the round
    /// key XOR in two instructions.
    AesNi = 5,
    /// GFNI: `gf2p8affineinv` computes the S-box in a single instruction.
    Gfni = 6,
}

impl Backend {
    fn from_u8(v: u8) -> Self {
        match v {
            1 => Backend::Sse2,
            2 => Backend::Ssse3,
            3 => Backend::Avx2,
            4 => Backend::Avx512Vbmi,
            5 => Backend::AesNi,
            6 => Backend::Gfni,
            _ => Backend::Fallback,
        }
    }

    /// Human-readable name, handy for logging which path a build actually took.
    pub fn name(self) -> &'static str {
        match self {
            Backend::Fallback => "portable",
            Backend::Sse2 => "x86_64/sse2",
            Backend::Ssse3 => "x86_64/ssse3",
            Backend::Avx2 => "x86_64/avx2",
            Backend::Avx512Vbmi => "x86_64/avx512vbmi",
            Backend::AesNi => "x86_64/aes-ni",
            Backend::Gfni => "x86_64/gfni",
        }
    }
}

/// `u8::MAX` means "not probed yet"; any other value is a cached [`Backend`].
const UNPROBED: u8 = u8::MAX;
static SELECTED: AtomicU8 = AtomicU8::new(UNPROBED);

/// Probes the host CPU. Called at most once per process in practice; a benign
/// race just means two threads compute the same answer.
fn detect() -> Backend {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        // The AES-hardware backends come first: Pich256's confusion layer *is*
        // the Rijndael S-box, so these compute it directly instead of emulating
        // a 256-entry table with byte shuffles. That beats every vector path
        // here regardless of how wide the vector units are.
        //
        // AES-NI is preferred over GFNI even though `gf2p8affineinv` is one
        // instruction to `aesenclast`'s two, because `aesenclast` also absorbs
        // the round's key XOR, and it measures consistently faster on the
        // hardware this was developed on (3.7 vs 4.0 ns/byte end to end). Any
        // CPU with GFNI has AES-NI too, so GFNI is in practice a documented
        // alternative reachable through `force_backend` rather than a path the
        // detector picks; re-run `examples/arch_bench.rs` before assuming the
        // ordering holds on a different microarchitecture.
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("ssse3") {
            return Backend::AesNi;
        }
        if is_x86_feature_detected!("gfni") {
            return Backend::Gfni;
        }

        // No AES hardware: fall back to emulating the table with byte shuffles.
        // Widest first. AVX-512 needs all four sub-features: `f` for the base
        // 512-bit encoding, `bw` for byte/word ops and the 64-lane mask,
        // `vbmi` for `vpermi2b`, and `vl` for the 128/256-bit forms.
        if is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vl")
            && is_x86_feature_detected!("avx512vbmi")
        {
            return Backend::Avx512Vbmi;
        }
        if is_x86_feature_detected!("avx2") {
            return Backend::Avx2;
        }
        if is_x86_feature_detected!("ssse3") {
            return Backend::Ssse3;
        }
        // SSE2 is architecturally guaranteed on x86_64, so this is the floor.
        Backend::Sse2
    }

    #[cfg(not(all(feature = "simd", target_arch = "x86_64")))]
    {
        Backend::Fallback
    }
}

/// The backend in use, probing the CPU on the first call and caching the result.
#[inline]
pub fn backend() -> Backend {
    let cached = SELECTED.load(Ordering::Relaxed);
    if cached != UNPROBED {
        return Backend::from_u8(cached);
    }
    let chosen = detect();
    SELECTED.store(chosen as u8, Ordering::Relaxed);
    chosen
}

/// Forces a specific backend, overriding CPU detection.
///
/// Intended for tests and benchmarks that want to compare paths within one
/// process. Selecting a backend the host cannot execute will fault, so callers
/// must only downgrade to something [`detect`] would also have accepted.
pub fn force_backend(b: Backend) {
    SELECTED.store(b as u8, Ordering::Relaxed);
}

/// Restores automatic detection.
pub fn reset_backend() {
    SELECTED.store(UNPROBED, Ordering::Relaxed);
}

/// Every backend this host can actually execute, widest first, always ending
/// with [`Backend::Fallback`].
///
/// Tests and benchmarks use this to exercise each supported path in turn rather
/// than only the one [`detect`] happens to pick, so an SSSE3 machine still
/// checks its SSSE3 code and an AVX-512 machine checks all four.
pub fn supported_backends() -> Vec<Backend> {
    let mut all = Vec::new();

    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        if is_x86_feature_detected!("aes") && is_x86_feature_detected!("ssse3") {
            all.push(Backend::AesNi);
        }
        if is_x86_feature_detected!("gfni") {
            all.push(Backend::Gfni);
        }
        if is_x86_feature_detected!("avx512f")
            && is_x86_feature_detected!("avx512bw")
            && is_x86_feature_detected!("avx512vl")
            && is_x86_feature_detected!("avx512vbmi")
        {
            all.push(Backend::Avx512Vbmi);
        }
        if is_x86_feature_detected!("avx2") {
            all.push(Backend::Avx2);
        }
        if is_x86_feature_detected!("ssse3") {
            all.push(Backend::Ssse3);
        }
        all.push(Backend::Sse2);
    }

    all.push(Backend::Fallback);
    all
}

/// One-line description of the host's relevant CPU features, for diagnostics.
pub fn cpu_summary() -> String {
    #[cfg(target_arch = "x86_64")]
    {
        let mut have = Vec::new();
        for f in [
            "sse2", "ssse3", "sse4.1", "avx", "avx2", "avx512f", "avx512bw", "avx512vl",
            "avx512vbmi", "bmi2", "sha", "aes", "gfni",
        ] {
            let present = match f {
                "sse2" => is_x86_feature_detected!("sse2"),
                "ssse3" => is_x86_feature_detected!("ssse3"),
                "sse4.1" => is_x86_feature_detected!("sse4.1"),
                "avx" => is_x86_feature_detected!("avx"),
                "avx2" => is_x86_feature_detected!("avx2"),
                "avx512f" => is_x86_feature_detected!("avx512f"),
                "avx512bw" => is_x86_feature_detected!("avx512bw"),
                "avx512vl" => is_x86_feature_detected!("avx512vl"),
                "avx512vbmi" => is_x86_feature_detected!("avx512vbmi"),
                "bmi2" => is_x86_feature_detected!("bmi2"),
                "sha" => is_x86_feature_detected!("sha"),
                "aes" => is_x86_feature_detected!("aes"),
                "gfni" => is_x86_feature_detected!("gfni"),
                _ => false,
            };
            if present {
                have.push(f);
            }
        }
        format!("x86_64 [{}]", have.join(" "))
    }

    #[cfg(not(target_arch = "x86_64"))]
    {
        format!("{} [no specialised backend]", std::env::consts::ARCH)
    }
}

/// Whether 256-bit integer vectors are available for the bulk keystream XOR.
///
/// Probed independently of [`Backend`] because the two are orthogonal: the
/// backend names an *S-box* strategy, and a CPU can have AES hardware without
/// AVX2 or AVX2 without AES hardware.
#[inline]
fn has_avx2() -> bool {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        static AVX2: AtomicU8 = AtomicU8::new(UNPROBED);
        let cached = AVX2.load(Ordering::Relaxed);
        if cached != UNPROBED {
            return cached == 1;
        }
        let ok = is_x86_feature_detected!("avx2");
        AVX2.store(ok as u8, Ordering::Relaxed);
        ok
    }

    #[cfg(not(all(feature = "simd", target_arch = "x86_64")))]
    false
}

/// Whether SHA-NI is available and will be used for SHA-256 compression.
///
/// Reported separately from [`Backend`] because the SHA extensions are an
/// independent CPUID bit: a CPU can have AVX-512 and no SHA-NI, or SSSE3 and
/// SHA-NI.
#[inline]
pub fn has_sha_ni() -> bool {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        static SHA_NI: AtomicU8 = AtomicU8::new(UNPROBED);
        let cached = SHA_NI.load(Ordering::Relaxed);
        if cached != UNPROBED {
            return cached == 1;
        }
        // `sha256rnds2` needs SHA-NI itself; the transposition around it uses
        // `pshufb` (SSSE3) and `pblendw` (SSE4.1).
        let ok = is_x86_feature_detected!("sha")
            && is_x86_feature_detected!("ssse3")
            && is_x86_feature_detected!("sse4.1");
        SHA_NI.store(ok as u8, Ordering::Relaxed);
        ok
    }

    #[cfg(not(all(feature = "simd", target_arch = "x86_64")))]
    false
}

// ==============================================================================
// Dispatched primitives
// ==============================================================================

/// Applies the AES S-box to every byte of `bytes`, in place.
#[inline]
pub fn sub_bytes(bytes: &mut [u8]) {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        match backend() {
            Backend::Gfni => return unsafe { x86_64::aes::sub_bytes_gfni(bytes) },
            Backend::AesNi => return unsafe { x86_64::aes::sub_bytes_aesni(bytes) },
            Backend::Avx512Vbmi => return unsafe { x86_64::sbox::sub_bytes_avx512(bytes) },
            Backend::Avx2 => return unsafe { x86_64::sbox::sub_bytes_avx2(bytes) },
            Backend::Ssse3 => return unsafe { x86_64::sbox::sub_bytes_ssse3(bytes) },
            _ => {}
        }
    }
    fallback::sub_bytes(bytes)
}

/// One cipher round: rotate the state right by 7, substitute every byte, then
/// XOR in the round key.
///
/// This is the hot path - `State::next_byte` calls it twice for every keystream
/// byte produced - which is why it is dispatched as a single fused operation
/// instead of three separate ones. The vector backends keep the state in an XMM
/// register across all three steps, avoiding two GPR<->XMM transfers per round.
#[inline]
pub fn round128(w: u128, sub_key: u128) -> u128 {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        match backend() {
            Backend::Gfni => return unsafe { x86_64::aes::round128_gfni(w, sub_key) },
            Backend::AesNi => return unsafe { x86_64::aes::round128_aesni(w, sub_key) },
            Backend::Avx512Vbmi => return unsafe { x86_64::sbox::round128_avx512(w, sub_key) },
            Backend::Avx2 => return unsafe { x86_64::sbox::round128_avx2(w, sub_key) },
            Backend::Ssse3 => return unsafe { x86_64::sbox::round128_ssse3(w, sub_key) },
            _ => {}
        }
    }
    fallback::round128(w, sub_key)
}

/// The keystream loop, generic over the round implementation.
///
/// Each backend instantiates this *inside* its own `#[target_feature]` wrapper
/// so that the round body inlines into the loop and the 128-bit state stays in a
/// register from one round to the next. Keeping the loop here rather than
/// duplicating it per backend means there is exactly one definition of what the
/// keystream is; the backends only supply the round.
#[inline(always)]
pub fn keystream_core(
    w: &mut u128,
    schedule: &[u128],
    round_index: &mut usize,
    out: &mut [u8],
    round: impl Fn(u128, u128) -> u128,
) {
    let len = schedule.len();
    debug_assert!(len > 0);

    let mut state = *w;
    let mut index = *round_index;

    // `index % len` recomputed per round would be a hardware division, since
    // `len` is not a compile-time constant. Track the wrapped position instead
    // and reset it with a well-predicted branch.
    let mut pos = index % len;

    for slot in out.iter_mut() {
        // Two rounds per output byte, matching `State::next_byte`: one round is
        // not enough to make the extracted byte unpredictable.
        for _ in 0..2 {
            state = round(state, schedule[pos]);
            pos += 1;
            if pos == len {
                pos = 0;
            }
        }
        index = index.wrapping_add(2);

        // The low nibble of the state's first little-endian byte names which of
        // the 16 state bytes is emitted.
        let bytes = state.to_le_bytes();
        *slot = bytes[(bytes[0] & 0x0f) as usize];
    }

    *w = state;
    *round_index = index;
}

/// Generates `out.len()` keystream bytes, advancing `w` and `round_index`.
///
/// Dispatch happens once per *call*, not once per round. That distinction is the
/// whole reason this function exists: a `#[target_feature]` function cannot be
/// inlined into a caller that does not carry the same features, so dispatching
/// per round would mean a genuine, non-inlinable call - plus a spill of the
/// 128-bit state to memory and back - for every one of the two rounds behind
/// each keystream byte. Hoisting the loop across the target-feature boundary
/// turns that into one call per buffer.
#[inline]
pub fn fill_keystream(w: &mut u128, schedule: &[u128], round_index: &mut usize, out: &mut [u8]) {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        match backend() {
            Backend::Gfni => {
                return unsafe { x86_64::aes::fill_keystream_gfni(w, schedule, round_index, out) };
            }
            Backend::AesNi => {
                return unsafe { x86_64::aes::fill_keystream_aesni(w, schedule, round_index, out) };
            }
            Backend::Avx512Vbmi => {
                return unsafe { x86_64::sbox::fill_keystream_avx512(w, schedule, round_index, out) };
            }
            Backend::Avx2 => {
                return unsafe { x86_64::sbox::fill_keystream_avx2(w, schedule, round_index, out) };
            }
            Backend::Ssse3 => {
                return unsafe { x86_64::sbox::fill_keystream_ssse3(w, schedule, round_index, out) };
            }
            _ => {}
        }
    }
    keystream_core(w, schedule, round_index, out, fallback::round128)
}

/// Rotates a 128-bit value left by `n` bits.
#[inline]
pub fn rotl128(x: u128, n: u32) -> u128 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        asm_int::rotl128(x, n)
    }
    #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
    {
        fallback::rotl128(x, n)
    }
}

/// Rotates a 128-bit value right by `n` bits.
#[inline]
pub fn rotr128(x: u128, n: u32) -> u128 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        asm_int::rotr128(x, n)
    }
    #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
    {
        fallback::rotr128(x, n)
    }
}

/// Truncating (wrapping) 128x128 -> low 128 bit multiplication.
#[inline]
pub fn mul128(a: u128, b: u128) -> u128 {
    #[cfg(all(feature = "asm", target_arch = "x86_64"))]
    {
        asm_int::mul128(a, b)
    }
    #[cfg(not(all(feature = "asm", target_arch = "x86_64")))]
    {
        fallback::mul128(a, b)
    }
}

/// `dst[i] ^= src[i]` over the overlap of the two slices.
#[inline]
pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        // Bulk XOR has nothing to do with the S-box, so it asks about vector
        // width directly rather than reading it off the backend.
        if backend() != Backend::Fallback {
            if has_avx2() {
                return unsafe { x86_64::sbox::xor_into_avx2(dst, src) };
            }
            // SSE2 is guaranteed on x86_64, so this needs no further check.
            return unsafe { x86_64::sbox::xor_into_sse2(dst, src) };
        }
    }
    fallback::xor_into(dst, src)
}

/// Compresses whole 64-byte SHA-256 blocks into `state`.
#[inline]
pub fn sha256_compress(state: &mut [u32; 8], blocks: &[u8]) {
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    {
        if has_sha_ni() {
            return unsafe { x86_64::sha::sha256_compress_shani(state, blocks) };
        }
    }
    fallback::sha256_compress(state, blocks)
}

// ==============================================================================
// Test support
// ==============================================================================

/// Runs `body` once per backend this host can execute, restoring automatic
/// detection afterwards even if `body` panics part way through.
///
/// [`force_backend`] mutates process-global state and `cargo test` runs tests on
/// parallel threads, so this serialises every test that pins a backend - across
/// modules, not just within one - behind a single lock.
#[cfg(test)]
pub(crate) fn for_each_backend(mut body: impl FnMut(Backend)) {
    use std::sync::Mutex;
    static BACKEND_LOCK: Mutex<()> = Mutex::new(());

    // A poisoned lock just means some earlier test panicked; the backend was
    // reset on the way out, so the state is still usable.
    let _guard = BACKEND_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let backends = supported_backends();
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for b in &backends {
            force_backend(*b);
            body(*b);
        }
    }));

    reset_backend();

    if let Err(payload) = outcome {
        std::panic::resume_unwind(payload);
    }
}

// ==============================================================================
// Tests
// ==============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sbox::SBOX;

    /// Deterministic pseudo-random bytes, so failures are reproducible.
    fn pattern(len: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn test_detected_backend_is_reported() {
        // Not an assertion about *which* backend, just that detection settles on
        // one and stays there.
        let first = backend();
        assert_eq!(first, backend());
        assert!(!first.name().is_empty());
    }

    #[test]
    fn test_supported_backends_includes_fallback_and_detected() {
        let all = supported_backends();
        assert!(all.contains(&Backend::Fallback));
        assert!(all.contains(&backend()));
    }

    #[test]
    fn test_sub_bytes_matches_table_for_every_length() {
        // Lengths chosen to exercise every vector width plus its scalar or
        // masked tail: 0, sub-16, exactly 16/32/64, and awkward remainders.
        for_each_backend(|b| {
            for len in [0usize, 1, 7, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 256, 257] {
                let input = pattern(len, 0xDEAD_BEEF ^ len as u64);

                let mut expected = input.clone();
                for byte in expected.iter_mut() {
                    *byte = SBOX[*byte as usize];
                }

                let mut actual = input.clone();
                sub_bytes(&mut actual);

                assert_eq!(actual, expected, "{} disagreed at len {len}", b.name());
            }
        });
    }

    #[test]
    fn test_sub_bytes_covers_all_256_inputs() {
        // Every byte value must map exactly as the table says, including the
        // 0x00 and 0xff boundaries where the pshufb saturation trick lives.
        let expected: Vec<u8> = (0..=255u8).map(|b| SBOX[b as usize]).collect();
        for_each_backend(|b| {
            let mut actual: Vec<u8> = (0..=255u8).collect();
            sub_bytes(&mut actual);
            assert_eq!(actual, expected, "{}", b.name());
        });
    }

    #[test]
    fn test_aes_hardware_matches_table_in_every_lane() {
        // The AES-hardware backends rest on two identities that are easy to get
        // subtly wrong:
        //
        //   aesenclast(InvShiftRows(x), k) == SubBytes(x) XOR k
        //   gf2p8affineinv(x, RIJNDAEL_MATRIX, 0x63) == SubBytes(x)
        //
        // A wrong `InvShiftRows` mask still produces *some* permutation of the
        // right bytes, so a test that only fed uniform input would pass. Feed
        // each of the 256 byte values through each of the 16 lane positions and
        // check the substitution lands in the lane it started in.
        for_each_backend(|b| {
            for high in 0..16u16 {
                let mut block = [0u8; 16];
                for (lane, slot) in block.iter_mut().enumerate() {
                    *slot = (high * 16 + lane as u16) as u8;
                }

                let expected: Vec<u8> = block.iter().map(|&x| SBOX[x as usize]).collect();

                let mut actual = block;
                sub_bytes(&mut actual);

                assert_eq!(actual.to_vec(), expected, "{} at block {high}", b.name());
            }

            // And the same coverage with the lane order reversed, so a mask that
            // happens to be self-inverse on the ascending pattern is caught too.
            for high in 0..16u16 {
                let mut block = [0u8; 16];
                for (lane, slot) in block.iter_mut().enumerate() {
                    *slot = (high * 16 + (15 - lane) as u16) as u8;
                }

                let expected: Vec<u8> = block.iter().map(|&x| SBOX[x as usize]).collect();

                let mut actual = block;
                sub_bytes(&mut actual);

                assert_eq!(actual.to_vec(), expected, "{} reversed at block {high}", b.name());
            }
        });
    }

    #[test]
    fn test_round128_matches_portable_reference() {
        for_each_backend(|b| {
            for i in 0..512u64 {
                let w = u128::from_le_bytes(pattern(16, i).try_into().unwrap());
                let k = u128::from_le_bytes(pattern(16, i ^ 0xA5A5_A5A5).try_into().unwrap());
                assert_eq!(
                    round128(w, k),
                    fallback::round128(w, k),
                    "{} at sample {i}",
                    b.name()
                );
            }
            // Degenerate inputs the random pattern will not hit.
            for (w, k) in [(0u128, 0u128), (u128::MAX, 0), (0, u128::MAX), (1, 1)] {
                assert_eq!(round128(w, k), fallback::round128(w, k), "{}", b.name());
            }
        });
    }

    #[test]
    fn test_fill_keystream_matches_portable_reference() {
        // A 16-entry schedule, as the cipher uses, plus a length that is not a
        // multiple of it so the round-key position wraps mid-buffer.
        let schedule: Vec<u128> = (0..16u128)
            .map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15_F39C_C060_5CED_C835) ^ (i << 100))
            .collect();

        let mut expected = vec![0u8; 300];
        let mut w_ref = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
        let mut idx_ref = 3usize;
        keystream_core(
            &mut w_ref,
            &schedule,
            &mut idx_ref,
            &mut expected,
            fallback::round128,
        );

        for_each_backend(|b| {
            let mut actual = vec![0u8; 300];
            let mut w = 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210u128;
            let mut idx = 3usize;
            fill_keystream(&mut w, &schedule, &mut idx, &mut actual);

            assert_eq!(actual, expected, "{} keystream", b.name());
            assert_eq!(w, w_ref, "{} final state", b.name());
            assert_eq!(idx, idx_ref, "{} final round index", b.name());
        });
    }

    #[test]
    fn test_rotates_match_portable_reference() {
        let samples = [
            0u128,
            1,
            u128::MAX,
            1 << 127,
            0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210,
        ];
        // Beyond 127 as well, to pin down the modulo-128 reduction.
        for &x in &samples {
            for n in 0..=256u32 {
                assert_eq!(rotl128(x, n), x.rotate_left(n & 127), "rotl {x:#x} by {n}");
                assert_eq!(rotr128(x, n), x.rotate_right(n & 127), "rotr {x:#x} by {n}");
            }
        }
    }

    #[test]
    fn test_rotate_left_and_right_are_inverses() {
        let x = 0x0F1E_2D3C_4B5A_6978_8796_A5B4_C3D2_E1F0u128;
        for n in 0..128u32 {
            assert_eq!(rotr128(rotl128(x, n), n), x);
        }
    }

    #[test]
    fn test_mul128_matches_portable_reference() {
        let samples = [
            0u128,
            1,
            2,
            u128::MAX,
            1 << 64,
            (1 << 64) - 1,
            0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210,
            0xFFFF_FFFF_FFFF_FFFF_0000_0000_0000_0001,
        ];
        for &a in &samples {
            for &b in &samples {
                assert_eq!(mul128(a, b), a.wrapping_mul(b), "{a:#x} * {b:#x}");
            }
        }
        for i in 0..256u64 {
            let a = u128::from_le_bytes(pattern(16, i).try_into().unwrap());
            let b = u128::from_le_bytes(pattern(16, i ^ 0x5A5A).try_into().unwrap());
            assert_eq!(mul128(a, b), a.wrapping_mul(b));
        }
    }

    #[test]
    fn test_xor_into_matches_portable_reference() {
        for_each_backend(|b| {
            for len in [0usize, 1, 15, 16, 31, 32, 33, 64, 100, 1000] {
                let src = pattern(len, 0x1234 ^ len as u64);
                let base = pattern(len, 0x9876 ^ len as u64);

                let mut expected = base.clone();
                fallback::xor_into(&mut expected, &src);

                let mut actual = base.clone();
                xor_into(&mut actual, &src);

                assert_eq!(actual, expected, "{} disagreed at len {len}", b.name());
            }
        });
    }

    #[test]
    fn test_xor_into_stops_at_the_shorter_slice() {
        // The vector paths advance raw pointers, so a length mismatch must be
        // clamped rather than run off the end of either buffer.
        let mut dst = vec![0xFFu8; 40];
        let src = vec![0x0Fu8; 10];
        xor_into(&mut dst, &src);

        assert!(dst[..10].iter().all(|&b| b == 0xF0));
        assert!(dst[10..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn test_sha256_compress_matches_portable_reference() {
        const INIT: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];
        // One, two and four blocks: the multi-block path keeps the state in
        // registers across iterations, so a single block would not catch a bug
        // in the feed-forward.
        for blocks in [1usize, 2, 4] {
            let data = pattern(blocks * 64, 0xC0FFEE + blocks as u64);

            let mut expected = INIT;
            fallback::sha256_compress(&mut expected, &data);

            let mut actual = INIT;
            sha256_compress(&mut actual, &data);

            assert_eq!(
                actual, expected,
                "sha256_compress disagreed at {blocks} blocks"
            );
        }
    }
}
