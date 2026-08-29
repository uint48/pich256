//! Vectorised AES S-box substitution and the fused cipher round for x86_64.
//!
//! # Why a 256-entry table is hard to vectorise
//!
//! `pshufb` / `vpshufb` (`_mm_shuffle_epi8`) is a *16-entry* byte shuffle: each
//! output byte is picked from one of 16 bytes of the source register using the
//! low nibble of the index. The Rijndael S-box has 256 entries, so it needs 16
//! such shuffles - one per table row - combined so that only the row matching
//! the index's high nibble contributes.
//!
//! The standard trick relies on a documented `pshufb` behaviour: **if the high
//! bit of an index byte is set, the corresponding output byte is zeroed.** So
//! for row `r` we bias the index so that only values in `16*r ..= 16*r+15`
//! survive:
//!
//! ```text
//! idx_r = index - 16*r                (wrapping, per byte)
//! sel_r = saturating_add_u8(idx_r, 0x70)
//! ```
//!
//! * `idx_r <= 0x0f` gives `sel_r <= 0x7f`: high bit clear, low nibble intact,
//!   so `pshufb` returns `row_r[idx_r]` - the wanted entry.
//! * `idx_r >= 0x10` gives `sel_r >= 0x80` (saturating at `0xff`): high bit set,
//!   so `pshufb` returns 0 and contributes nothing to the OR.
//!
//! Exactly one row is ever non-zero, so OR-ing the 16 shuffles reconstructs the
//! full 256-entry lookup.
//!
//! # When is this used?
//!
//! Only when the CPU has no AES hardware. Pich256's S-box *is* the Rijndael
//! S-box, so on anything from 2010 onwards [`super::aes`] computes it directly
//! with `aesenclast` or `gf2p8affineinv` and beats everything here by roughly 3x
//! end to end. These backends cover older x86_64 parts, and VMs or firmware that
//! mask off the AES feature bits.
//!
//! Against the *scalar* table in [`crate::arch::fallback`] the trade is subtler.
//! An L1 lookup is a single micro-op and modern cores sustain two per cycle,
//! whereas the shuffle sequence above costs roughly four micro-ops per byte; the
//! AVX2 path wins the cipher's latency-bound inner loop by about 7% and loses
//! the bulk throughput case outright. What it does buy unconditionally is
//! **constant time**: no memory address ever depends on secret data, so there is
//! no cache-timing side channel of the kind that has repeatedly broken
//! table-driven AES implementations - a property the AES-hardware paths share
//! and the scalar table does not.

use core::arch::x86_64::*;

use crate::sbox::SBOX;

/// Byte-shift applied to the index before each row's shuffle, so that a nibble
/// belonging to another row saturates its high bit and is zeroed by `pshufb`.
const PSHUFB_BIAS: i8 = 0x70;

// ==============================================================================
// SSSE3: 16 bytes per pass
// ==============================================================================

/// Substitutes all 16 bytes of `x` through the AES S-box.
///
/// The sixteen row lookups are deliberately kept *independent* of one another:
/// each derives its own biased index straight from `x` rather than from the
/// previous row's, and the results are combined by a four-deep OR tree instead
/// of a sixteen-deep OR chain. That drops the critical path from ~19 dependent
/// operations to ~7, which is what matters here - `round128` feeds this
/// function's output straight back into its next input, so the whole cipher runs
/// at the latency of this chain, not at its throughput.
#[inline]
#[target_feature(enable = "ssse3")]
unsafe fn sub_bytes_x16_ssse3(x: __m128i) -> __m128i {
    let bias = _mm_set1_epi8(PSHUFB_BIAS);

    /// One row of the table: shift the index into row `$r`'s window, saturate
    /// everything outside that window into the high-bit-set range so `pshufb`
    /// zeroes it, and look up.
    macro_rules! row {
        ($r:expr) => {{
            let row = $r * 16usize;
            let table = unsafe { _mm_loadu_si128(SBOX.as_ptr().add(row) as *const __m128i) };
            let shifted = _mm_sub_epi8(x, _mm_set1_epi8(row as u8 as i8));
            _mm_shuffle_epi8(table, _mm_adds_epu8(shifted, bias))
        }};
    }

    let (r0, r1, r2, r3) = (row!(0), row!(1), row!(2), row!(3));
    let (r4, r5, r6, r7) = (row!(4), row!(5), row!(6), row!(7));
    let (r8, r9, ra, rb) = (row!(8), row!(9), row!(10), row!(11));
    let (rc, rd, re, rf) = (row!(12), row!(13), row!(14), row!(15));

    // At most one row is non-zero for any given byte, so OR is a valid merge.
    let a = _mm_or_si128(_mm_or_si128(r0, r1), _mm_or_si128(r2, r3));
    let b = _mm_or_si128(_mm_or_si128(r4, r5), _mm_or_si128(r6, r7));
    let c = _mm_or_si128(_mm_or_si128(r8, r9), _mm_or_si128(ra, rb));
    let d = _mm_or_si128(_mm_or_si128(rc, rd), _mm_or_si128(re, rf));

    _mm_or_si128(_mm_or_si128(a, b), _mm_or_si128(c, d))
}

/// In-place AES S-box over an arbitrary-length slice, 16 bytes at a time.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "ssse3")]
pub unsafe fn sub_bytes_ssse3(bytes: &mut [u8]) {
    unsafe {
        let mut chunks = bytes.chunks_exact_mut(16);
        for chunk in &mut chunks {
            let p = chunk.as_mut_ptr() as *mut __m128i;
            _mm_storeu_si128(p, sub_bytes_x16_ssse3(_mm_loadu_si128(p)));
        }
        crate::arch::fallback::sub_bytes(chunks.into_remainder());
    }
}

// ==============================================================================
// AVX2: 32 bytes per pass
// ==============================================================================

/// Substitutes all 32 bytes of `x`. `vpshufb` shuffles the two 128-bit lanes
/// independently, so the table register simply holds the same row twice.
/// Structured as an OR tree over independent rows, for the reason given on
/// [`sub_bytes_x16_ssse3`].
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sub_bytes_x32_avx2(x: __m256i) -> __m256i {
    let bias = _mm256_set1_epi8(PSHUFB_BIAS);

    macro_rules! row {
        ($r:expr) => {{
            let row = $r * 16usize;
            let half = unsafe { _mm_loadu_si128(SBOX.as_ptr().add(row) as *const __m128i) };
            let table = _mm256_broadcastsi128_si256(half);
            let shifted = _mm256_sub_epi8(x, _mm256_set1_epi8(row as u8 as i8));
            _mm256_shuffle_epi8(table, _mm256_adds_epu8(shifted, bias))
        }};
    }

    let (r0, r1, r2, r3) = (row!(0), row!(1), row!(2), row!(3));
    let (r4, r5, r6, r7) = (row!(4), row!(5), row!(6), row!(7));
    let (r8, r9, ra, rb) = (row!(8), row!(9), row!(10), row!(11));
    let (rc, rd, re, rf) = (row!(12), row!(13), row!(14), row!(15));

    let a = _mm256_or_si256(_mm256_or_si256(r0, r1), _mm256_or_si256(r2, r3));
    let b = _mm256_or_si256(_mm256_or_si256(r4, r5), _mm256_or_si256(r6, r7));
    let c = _mm256_or_si256(_mm256_or_si256(r8, r9), _mm256_or_si256(ra, rb));
    let d = _mm256_or_si256(_mm256_or_si256(rc, rd), _mm256_or_si256(re, rf));

    _mm256_or_si256(_mm256_or_si256(a, b), _mm256_or_si256(c, d))
}

/// The paired-row half of the AVX2 S-box.
///
/// `dup` must hold the same 16 bytes in *both* 128-bit lanes. `vpshufb` treats a
/// YMM register as two independent 128-bit shuffles, so one YMM table can hold
/// **two** rows of the S-box - row `2p` in the low lane, row `2p+1` in the high
/// lane - and cover both in a single instruction. That halves the sixteen
/// `pshufb` of [`sub_bytes_x16_ssse3`] to eight and, just as importantly, cuts
/// the table registers from sixteen to eight, which is what lets them stay
/// resident instead of being reloaded from `.rodata` on every round.
///
/// The result is *not* folded: the low lane carries the even rows' hits and the
/// high lane the odd rows'. Folding is left to the caller because the keystream
/// loop can fold and re-duplicate in one lane-crossing shuffle, whereas a
/// standalone caller wants a plain 128-bit answer.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sub_bytes_paired_avx2(dup: __m256i) -> __m256i {
    let bias = _mm256_set1_epi8(PSHUFB_BIAS);

    /// Rows `2p` (low lane) and `2p+1` (high lane) in one shuffle.
    macro_rules! pair {
        ($p:expr) => {{
            let lo_row = $p * 32usize;
            let hi_row = lo_row + 16;
            let table = unsafe {
                _mm256_set_m128i(
                    _mm_loadu_si128(SBOX.as_ptr().add(hi_row) as *const __m128i),
                    _mm_loadu_si128(SBOX.as_ptr().add(lo_row) as *const __m128i),
                )
            };
            let shift = _mm256_set_m128i(
                _mm_set1_epi8(hi_row as u8 as i8),
                _mm_set1_epi8(lo_row as u8 as i8),
            );
            let shifted = _mm256_sub_epi8(dup, shift);
            _mm256_shuffle_epi8(table, _mm256_adds_epu8(shifted, bias))
        }};
    }

    let (p0, p1, p2, p3) = (pair!(0), pair!(1), pair!(2), pair!(3));
    let (p4, p5, p6, p7) = (pair!(4), pair!(5), pair!(6), pair!(7));

    let a = _mm256_or_si256(_mm256_or_si256(p0, p1), _mm256_or_si256(p2, p3));
    let b = _mm256_or_si256(_mm256_or_si256(p4, p5), _mm256_or_si256(p6, p7));
    _mm256_or_si256(a, b)
}

/// Substitutes the 16 bytes of `x` via the paired-row lookup, folding the two
/// lanes back into one 128-bit result.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn sub_bytes_x16_avx2(x: __m128i) -> __m128i {
    let merged = unsafe { sub_bytes_paired_avx2(_mm256_broadcastsi128_si256(x)) };
    // Exactly one of the 16 rows is non-zero for any given byte, whichever lane
    // it landed in, so OR-ing the lanes recovers the substitution.
    _mm_or_si128(
        _mm256_castsi256_si128(merged),
        _mm256_extracti128_si256(merged, 1),
    )
}

/// Rotates a lane-duplicated 128-bit state right by 7 bits, keeping it
/// duplicated. Every operation here is per-lane, so both halves of the YMM stay
/// in lockstep; see [`rotr7_x128`] for the derivation.
#[inline]
#[target_feature(enable = "avx2")]
unsafe fn rotr7_dup_avx2(x: __m256i) -> __m256i {
    let down = _mm256_srli_epi64(x, 7);
    let up = _mm256_slli_epi64(x, 57);
    // `vpshufd` shuffles dwords within each 128-bit lane, so `[2,3,0,1]`
    // exchanges the two 64-bit halves of each lane independently.
    let crossed = _mm256_shuffle_epi32(up, 0x4E);
    _mm256_or_si256(down, crossed)
}

/// In-place AES S-box over an arbitrary-length slice, 32 bytes at a time,/// In-place AES S-box over an arbitrary-length slice, 32 bytes at a time,
/// falling back to the SSSE3 path for a 16-byte tail.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "avx2")]
pub unsafe fn sub_bytes_avx2(bytes: &mut [u8]) {
    unsafe {
        let mut chunks = bytes.chunks_exact_mut(32);
        for chunk in &mut chunks {
            let p = chunk.as_mut_ptr() as *mut __m256i;
            _mm256_storeu_si256(p, sub_bytes_x32_avx2(_mm256_loadu_si256(p)));
        }
        // AVX2 implies SSSE3, so the tail can use the narrower vector path.
        sub_bytes_ssse3(chunks.into_remainder());
    }
}

// ==============================================================================
// AVX-512 VBMI: the whole 256-entry table in two instructions
// ==============================================================================

/// `vpermi2b` (`_mm512_permutex2var_epi8`) indexes a *128-byte* table spread
/// across two ZMM registers using the low 7 bits of each index byte. Two of them
/// cover entries `0..=127` and `128..=255`; the index's bit 7 then selects which
/// result to keep, via a mask blend. Four instructions replace sixteen shuffles.
#[inline]
#[target_feature(enable = "avx512f,avx512bw,avx512vl,avx512vbmi")]
unsafe fn sub_bytes_x64_avx512(x: __m512i) -> __m512i {
    unsafe {
        let t0 = _mm512_loadu_si512(SBOX.as_ptr().add(0) as *const __m512i);
        let t1 = _mm512_loadu_si512(SBOX.as_ptr().add(64) as *const __m512i);
        let t2 = _mm512_loadu_si512(SBOX.as_ptr().add(128) as *const __m512i);
        let t3 = _mm512_loadu_si512(SBOX.as_ptr().add(192) as *const __m512i);

        let lo = _mm512_permutex2var_epi8(t0, x, t1); // entries 0x00..=0x7f
        let hi = _mm512_permutex2var_epi8(t2, x, t3); // entries 0x80..=0xff
        let high_bit = _mm512_movepi8_mask(x); // 1 where the index is >= 0x80

        _mm512_mask_blend_epi8(high_bit, lo, hi)
    }
}

/// In-place AES S-box over an arbitrary-length slice, 64 bytes at a time.
/// The tail is handled with masked load/store, so no scalar fallback is needed.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "avx512f,avx512bw,avx512vl,avx512vbmi")]
pub unsafe fn sub_bytes_avx512(bytes: &mut [u8]) {
    unsafe {
        let mut chunks = bytes.chunks_exact_mut(64);
        for chunk in &mut chunks {
            let p = chunk.as_mut_ptr() as *mut __m512i;
            _mm512_storeu_si512(p, sub_bytes_x64_avx512(_mm512_loadu_si512(p as *const __m512i)));
        }

        let rest = chunks.into_remainder();
        if !rest.is_empty() {
            // A 64-bit lane mask with one bit set per live byte.
            let mask: __mmask64 = (1u64 << rest.len()) - 1;
            let v = _mm512_maskz_loadu_epi8(mask, rest.as_ptr() as *const i8);
            let s = sub_bytes_x64_avx512(v);
            _mm512_mask_storeu_epi8(rest.as_mut_ptr() as *mut i8, mask, s);
        }
    }
}

// ==============================================================================
// The fused cipher round
// ==============================================================================

/// Rotates a 128-bit value right by 7 bits while it stays in an XMM register.
///
/// SSE2 has no cross-lane bit shift, only per-64-bit-lane ones, so the rotate is
/// synthesised as `(x >> 7) | swap64(x << 57)`:
///
/// ```text
/// lo' = (lo >> 7) | (hi << 57)
/// hi' = (hi >> 7) | (lo << 57)
/// ```
///
/// `_mm_shuffle_epi32(_, 0x4E)` reorders the 32-bit lanes as `[2,3,0,1]`, i.e.
/// it exchanges the two 64-bit halves, supplying each half with the other's
/// spilled bits.
#[inline]
#[target_feature(enable = "sse2")]
pub(super) unsafe fn rotr7_x128(x: __m128i) -> __m128i {
    // Register-only intrinsics: no memory is touched, so no `unsafe` block is
    // needed inside this `unsafe fn`.
    let down = _mm_srli_epi64(x, 7);
    let up = _mm_slli_epi64(x, 57);
    let crossed = _mm_shuffle_epi32(up, 0x4E);
    _mm_or_si128(down, crossed)
}

/// One cipher round with the state kept in a vector register throughout:
/// rotate right by 7, bytewise S-box, XOR the round key.
///
/// Keeping all three steps in XMM avoids two GPR<->XMM round trips per round,
/// which matters because `State::next_byte` runs two rounds for every single
/// keystream byte.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[inline]
#[target_feature(enable = "ssse3")]
pub unsafe fn round128_ssse3(w: u128, sub_key: u128) -> u128 {
    unsafe {
        let state = _mm_loadu_si128(&w as *const u128 as *const __m128i);
        let key = _mm_loadu_si128(&sub_key as *const u128 as *const __m128i);

        let mixed = _mm_xor_si128(sub_bytes_x16_ssse3(rotr7_x128(state)), key);

        let mut out = 0u128;
        _mm_storeu_si128(&mut out as *mut u128 as *mut __m128i, mixed);
        out
    }
}

/// AVX-512 VBMI variant of [`round128_ssse3`]; identical apart from the S-box,
/// which becomes a pair of `vpermi2b` on the low 128 bits of a ZMM register.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[inline]
#[target_feature(enable = "avx512f,avx512bw,avx512vl,avx512vbmi")]
pub unsafe fn round128_avx512(w: u128, sub_key: u128) -> u128 {
    unsafe {
        let state = _mm_loadu_si128(&w as *const u128 as *const __m128i);
        let key = _mm_loadu_si128(&sub_key as *const u128 as *const __m128i);

        let rotated = _mm512_castsi128_si512(rotr7_x128(state));
        let substituted = _mm512_castsi512_si128(sub_bytes_x64_avx512(rotated));

        let mut out = 0u128;
        _mm_storeu_si128(
            &mut out as *mut u128 as *mut __m128i,
            _mm_xor_si128(substituted, key),
        );
        out
    }
}

// ==============================================================================
// Bulk XOR (keystream application)
// ==============================================================================

/// `dst ^= src` over 32 bytes per pass.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "avx2")]
pub unsafe fn xor_into_avx2(dst: &mut [u8], src: &[u8]) {
    unsafe {
        let n = dst.len().min(src.len());
        let (mut d, mut s) = (dst.as_mut_ptr(), src.as_ptr());
        let mut left = n;

        while left >= 32 {
            let a = _mm256_loadu_si256(d as *const __m256i);
            let b = _mm256_loadu_si256(s as *const __m256i);
            _mm256_storeu_si256(d as *mut __m256i, _mm256_xor_si256(a, b));
            d = d.add(32);
            s = s.add(32);
            left -= 32;
        }
        while left >= 16 {
            let a = _mm_loadu_si128(d as *const __m128i);
            let b = _mm_loadu_si128(s as *const __m128i);
            _mm_storeu_si128(d as *mut __m128i, _mm_xor_si128(a, b));
            d = d.add(16);
            s = s.add(16);
            left -= 16;
        }
        crate::arch::fallback::xor_into(
            core::slice::from_raw_parts_mut(d, left),
            core::slice::from_raw_parts(s, left),
        );
    }
}

/// `dst ^= src` over 16 bytes per pass. SSE2 is part of the x86_64 baseline, so
/// this path needs no runtime check at all.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "sse2")]
pub unsafe fn xor_into_sse2(dst: &mut [u8], src: &[u8]) {
    unsafe {
        let n = dst.len().min(src.len());
        let (mut d, mut s) = (dst.as_mut_ptr(), src.as_ptr());
        let mut left = n;

        while left >= 16 {
            let a = _mm_loadu_si128(d as *const __m128i);
            let b = _mm_loadu_si128(s as *const __m128i);
            _mm_storeu_si128(d as *mut __m128i, _mm_xor_si128(a, b));
            d = d.add(16);
            s = s.add(16);
            left -= 16;
        }
        crate::arch::fallback::xor_into(
            core::slice::from_raw_parts_mut(d, left),
            core::slice::from_raw_parts(s, left),
        );
    }
}

// ==============================================================================
// Keystream generation
// ==============================================================================

/// SSSE3/AVX2 keystream loop.
///
/// The dispatch in [`crate::arch::fill_keystream`] lands here once per buffer;
/// [`crate::arch::keystream_core`] is then inlined into this target-feature
/// context, which lets `round128_ssse3` inline in turn and keeps the 128-bit
/// state resident in an XMM register across every round of the buffer.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "ssse3")]
pub unsafe fn fill_keystream_ssse3(
    w: &mut u128,
    schedule: &[u128],
    round_index: &mut usize,
    out: &mut [u8],
) {
    crate::arch::keystream_core(w, schedule, round_index, out, |state, key| unsafe {
        round128_ssse3(state, key)
    });
}

/// AVX-512 VBMI keystream loop; see [`fill_keystream_ssse3`].
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "avx512f,avx512bw,avx512vl,avx512vbmi")]
pub unsafe fn fill_keystream_avx512(
    w: &mut u128,
    schedule: &[u128],
    round_index: &mut usize,
    out: &mut [u8],
) {
    crate::arch::keystream_core(w, schedule, round_index, out, |state, key| unsafe {
        round128_avx512(state, key)
    });
}

/// AVX2 round, using the two-rows-per-register S-box of
/// [`sub_bytes_x16_avx2`]. The rotate stays SSE2 - there is no 256-bit work to
/// do on a 128-bit state.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[inline]
#[target_feature(enable = "avx2")]
pub unsafe fn round128_avx2(w: u128, sub_key: u128) -> u128 {
    unsafe {
        let state = _mm_loadu_si128(&w as *const u128 as *const __m128i);
        let key = _mm_loadu_si128(&sub_key as *const u128 as *const __m128i);

        let mixed = _mm_xor_si128(sub_bytes_x16_avx2(rotr7_x128(state)), key);

        let mut out = 0u128;
        _mm_storeu_si128(&mut out as *mut u128 as *mut __m128i, mixed);
        out
    }
}

/// AVX2 keystream loop, with the state held **lane-duplicated** in a YMM
/// register for the whole buffer.
///
/// [`crate::arch::keystream_core`] is the normative definition of the keystream,
/// and `test_fill_keystream_matches_repeated_next_byte` plus
/// `test_keystream_is_backend_independent` check this loop against it byte for
/// byte. It is spelled out separately only because of where the lane fold goes.
///
/// [`sub_bytes_paired_avx2`] wants its input in both lanes and leaves its output
/// split across them. Driving it from the generic core would mean folding down
/// to one XMM after every round and broadcasting back up before the next - two
/// lane-crossing shuffles at three cycles each, on the critical path of a loop
/// that is purely latency bound, since each round's output is the next round's
/// input. Keeping the state duplicated collapses both into a single
/// `vperm2i128` + `vpor`: OR-ing a register with its own lane-swapped self both
/// merges the halves and leaves the merged value in *both* lanes, ready for the
/// next round.
///
/// The round key is pulled straight from the schedule with `vbroadcasti128`,
/// which duplicates a 16-byte memory operand across both lanes as part of the
/// load, so it costs nothing extra.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here. The slice arguments are
/// ordinary Rust slices and need no further guarantees.
#[target_feature(enable = "avx2")]
pub unsafe fn fill_keystream_avx2(
    w: &mut u128,
    schedule: &[u128],
    round_index: &mut usize,
    out: &mut [u8],
) {
    unsafe {
        let len = schedule.len();
        debug_assert!(len > 0);

        let mut state =
            _mm256_broadcastsi128_si256(_mm_loadu_si128(w as *const u128 as *const __m128i));

        let mut index = *round_index;
        // `index % len` per round would be a hardware division; track the
        // wrapped position separately, as `keystream_core` does.
        let mut pos = index % len;

        let mut bytes = [0u8; 16];

        for slot in out.iter_mut() {
            // Two rounds per output byte, matching `State::next_byte`.
            for _ in 0..2 {
                let key = _mm256_broadcastsi128_si256(_mm_loadu_si128(
                    schedule.as_ptr().add(pos) as *const __m128i,
                ));

                let substituted = sub_bytes_paired_avx2(rotr7_dup_avx2(state));
                // Fold the odd-row lane onto the even-row lane and end up with
                // the result duplicated across both lanes again.
                let folded = _mm256_or_si256(
                    substituted,
                    _mm256_permute2x128_si256(substituted, substituted, 0x01),
                );
                state = _mm256_xor_si256(folded, key);

                pos += 1;
                if pos == len {
                    pos = 0;
                }
            }
            index = index.wrapping_add(2);

            // Both lanes are identical, so the low one is the whole state.
            _mm_storeu_si128(
                bytes.as_mut_ptr() as *mut __m128i,
                _mm256_castsi256_si128(state),
            );
            *slot = bytes[(bytes[0] & 0x0f) as usize];
        }

        _mm_storeu_si128(
            w as *mut u128 as *mut __m128i,
            _mm256_castsi256_si128(state),
        );
        *round_index = index;
    }
}
