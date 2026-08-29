//! SHA-256 block compression using the Intel SHA extensions (SHA-NI).
//!
//! SHA-NI is an entirely separate ISA extension from AES-NI - it accelerates
//! SHA-1/SHA-256 only - so using it here does not conflict with the decision to
//! keep the cipher core free of AES hardware support. It speeds up
//! [`crate::kdf::derive_256bit_key`], which runs four SHA-256 compressions per
//! `Pich256::new`.
//!
//! # The three instructions
//!
//! * `sha256rnds2 xmm1, xmm2, xmm0` performs **two** rounds of the compression
//!   function. The eight working variables are held in two registers in a
//!   rotated layout - `ABEF` and `CDGH` - rather than as `a..h` in order, and
//!   the two round constants (already summed with the message words) arrive in
//!   the low two dwords of `xmm0`.
//! * `sha256msg1 xmm1, xmm2` computes the `sigma0` half of the message schedule
//!   for four words at once.
//! * `sha256msg2 xmm1, xmm2` finishes those words with the `sigma1` half.
//!
//! Together they replace the 64-iteration scalar loop with 16 groups of four
//! rounds, each group costing two `sha256rnds2` plus a few shuffles.
//!
//! # Register layout
//!
//! The state arrives as `[a, b, c, d, e, f, g, h]` in memory order and has to be
//! transposed into the `ABEF`/`CDGH` pairing the instruction expects; the same
//! transposition is undone on the way out. That is what the `shuffle`/`alignr`/
//! `blend` preamble and epilogue do - they are pure data movement, not part of
//! the hash.

use core::arch::x86_64::*;

use crate::arch::fallback::SHA256_K;

/// Compresses `blocks` (a whole number of padded 64-byte blocks) into `state`.
///
/// # Safety
///
/// The caller must have verified that the CPU supports `sha`, `sse2`, `ssse3`
/// and `sse4.1`. `blocks.len()` must be a multiple of 64.
#[target_feature(enable = "sha,sse2,ssse3,sse4.1")]
pub unsafe fn sha256_compress_shani(state: &mut [u32; 8], blocks: &[u8]) {
    unsafe {
        debug_assert_eq!(blocks.len() % 64, 0);

        // Reverses the bytes within each 32-bit word, turning the big-endian message
        // words of FIPS 180-4 into the little-endian dwords the CPU works with.
        let byte_swap = _mm_set_epi64x(0x0c0d_0e0f_0809_0a0b_u64 as i64, 0x0405_0607_0001_0203);

        // ---- transpose [a b c d e f g h] -> (ABEF, CDGH) -------------------------
        // Labels below name the dwords from most- to least-significant, matching
        // the convention used in Intel's reference sequence.
        let mut tmp = _mm_loadu_si128(state.as_ptr() as *const __m128i); // DCBA
        let mut state1 = _mm_loadu_si128(state.as_ptr().add(4) as *const __m128i); // HGFE

        tmp = _mm_shuffle_epi32(tmp, 0xB1); // CDAB
        state1 = _mm_shuffle_epi32(state1, 0x1B); // EFGH
        let mut state0 = _mm_alignr_epi8(tmp, state1, 8); // ABEF
        state1 = _mm_blend_epi16(state1, tmp, 0xF0); // CDGH

        for chunk in blocks.chunks_exact(64) {
            let abef_save = state0;
            let cdgh_save = state1;

            let p = chunk.as_ptr();
            let mut m0 = _mm_shuffle_epi8(_mm_loadu_si128(p as *const __m128i), byte_swap);
            let mut m1 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(16) as *const __m128i), byte_swap);
            let mut m2 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(32) as *const __m128i), byte_swap);
            let mut m3 = _mm_shuffle_epi8(_mm_loadu_si128(p.add(48) as *const __m128i), byte_swap);

            // Four rounds: add the group's round constants to the message words and
            // feed the low then the high dword pair to `sha256rnds2`.
            macro_rules! four_rounds {
                ($group:expr, $cur:expr) => {{
                    let k = _mm_loadu_si128(SHA256_K.as_ptr().add(4 * $group) as *const __m128i);
                    let msg = _mm_add_epi32($cur, k);
                    state1 = _mm_sha256rnds2_epu32(state1, state0, msg);
                    let msg_high = _mm_shuffle_epi32(msg, 0x0E);
                    state0 = _mm_sha256rnds2_epu32(state0, state1, msg_high);
                }};
            }

            // `sigma1` half of the schedule: the next quartet of message words is
            // completed from the current one and the previous one.
            macro_rules! schedule_msg2 {
                ($cur:ident, $next:ident, $prev:ident) => {{
                    let carried = _mm_alignr_epi8($cur, $prev, 4);
                    $next = _mm_add_epi32($next, carried);
                    $next = _mm_sha256msg2_epu32($next, $cur);
                }};
            }

            // Rounds 0-15 read their words straight from the block; `sha256msg1`
            // starts building the schedule two groups ahead of where it is needed.
            four_rounds!(0, m0);

            four_rounds!(1, m1);
            m0 = _mm_sha256msg1_epu32(m0, m1);

            four_rounds!(2, m2);
            m1 = _mm_sha256msg1_epu32(m1, m2);

            // From here on the interleaving is fixed: rounds, then finish the
            // schedule quartet that will be consumed two groups later, then start
            // the next one.
            four_rounds!(3, m3);
            schedule_msg2!(m3, m0, m2);
            m2 = _mm_sha256msg1_epu32(m2, m3);

            four_rounds!(4, m0);
            schedule_msg2!(m0, m1, m3);
            m3 = _mm_sha256msg1_epu32(m3, m0);

            four_rounds!(5, m1);
            schedule_msg2!(m1, m2, m0);
            m0 = _mm_sha256msg1_epu32(m0, m1);

            four_rounds!(6, m2);
            schedule_msg2!(m2, m3, m1);
            m1 = _mm_sha256msg1_epu32(m1, m2);

            four_rounds!(7, m3);
            schedule_msg2!(m3, m0, m2);
            m2 = _mm_sha256msg1_epu32(m2, m3);

            four_rounds!(8, m0);
            schedule_msg2!(m0, m1, m3);
            m3 = _mm_sha256msg1_epu32(m3, m0);

            four_rounds!(9, m1);
            schedule_msg2!(m1, m2, m0);
            m0 = _mm_sha256msg1_epu32(m0, m1);

            four_rounds!(10, m2);
            schedule_msg2!(m2, m3, m1);
            m1 = _mm_sha256msg1_epu32(m1, m2);

            four_rounds!(11, m3);
            schedule_msg2!(m3, m0, m2);
            m2 = _mm_sha256msg1_epu32(m2, m3);

            four_rounds!(12, m0);
            schedule_msg2!(m0, m1, m3);
            m3 = _mm_sha256msg1_epu32(m3, m0);

            // The final words are all in hand now, so no more `sha256msg1`.
            four_rounds!(13, m1);
            schedule_msg2!(m1, m2, m0);

            four_rounds!(14, m2);
            schedule_msg2!(m2, m3, m1);

            four_rounds!(15, m3);

            // Feed-forward: the block's output is added to its input state.
            state0 = _mm_add_epi32(state0, abef_save);
            state1 = _mm_add_epi32(state1, cdgh_save);
        }

        // ---- transpose (ABEF, CDGH) -> [a b c d e f g h] ------------------------
        tmp = _mm_shuffle_epi32(state0, 0x1B); // FEBA
        state1 = _mm_shuffle_epi32(state1, 0xB1); // DCHG
        state0 = _mm_blend_epi16(tmp, state1, 0xF0); // DCBA
        state1 = _mm_alignr_epi8(state1, tmp, 8); // HGFE

        _mm_storeu_si128(state.as_mut_ptr() as *mut __m128i, state0);
        _mm_storeu_si128(state.as_mut_ptr().add(4) as *mut __m128i, state1);
    }
}
