//! S-box backends built on the CPU's AES hardware.
//!
//! Pich256's confusion layer *is* the Rijndael S-box, so the substitution the
//! cipher needs is exactly the one x86_64 has had in silicon since Westmere.
//! Two unrelated instruction sets can produce it, and this module implements
//! both.
//!
//! # AES-NI: `aesenclast`
//!
//! `aesenclast(x, k)` is a whole final AES round:
//!
//! ```text
//! aesenclast(x, k) = SubBytes(ShiftRows(x)) XOR k
//! ```
//!
//! `SubBytes` is bytewise and `ShiftRows` is a byte permutation, so the two
//! commute, and `ShiftRows` can be cancelled by permuting the input first:
//!
//! ```text
//! aesenclast(InvShiftRows(x), k) = SubBytes(ShiftRows(InvShiftRows(x))) XOR k
//!                                = SubBytes(x) XOR k
//! ```
//!
//! `InvShiftRows` is one `pshufb`. That leaves **two instructions** for the
//! S-box - and note the `XOR k` comes along for free, so `aesenclast` absorbs
//! the round's key-mixing step as well. A Pich256 round becomes the rotate,
//! one `pshufb`, and one `aesenclast`.
//!
//! # GFNI: `gf2p8affineinv`
//!
//! `vgf2p8affineinvqb(x, A, b)` inverts each byte in GF(2^8) modulo the AES
//! polynomial `0x11B` and then applies the affine map `A*inv(x) + b` over GF(2).
//! That is the textbook definition of the Rijndael S-box, so with `A` set to the
//! Rijndael matrix and `b = 0x63` the whole substitution is a **single
//! instruction** - no permutation needed, because there is no `ShiftRows` baked
//! in. The key XOR then costs one separate `pxor`, so both backends come out at
//! two instructions per round for the substitute-and-mix step.
//!
//! # Correctness
//!
//! Both identities, and the two magic constants below, are checked against the
//! `SBOX` table for all 256 byte values in every one of the 16 lane positions by
//! `test_sub_bytes_covers_all_256_inputs` and
//! `test_aes_hardware_matches_table_in_every_lane`. They are not taken on faith.

use core::arch::x86_64::*;

use super::sbox::rotr7_x128;

/// `InvShiftRows` as a `pshufb` gather mask: `out[i] = in[INV_SHIFT_ROWS[i]]`.
///
/// AES numbers the state column-major, so byte `i` sits at row `i % 4`, column
/// `i / 4`, and `ShiftRows` rotates row `r` left by `r` columns:
/// `ShiftRows(x)[r + 4c] = x[r + 4*((c + r) mod 4)]`. This table is that
/// permutation inverted, so that applying it and then `aesenclast`'s built-in
/// `ShiftRows` leaves the bytes where they started.
const INV_SHIFT_ROWS: [u8; 16] = [0, 13, 10, 7, 4, 1, 14, 11, 8, 5, 2, 15, 12, 9, 6, 3];

/// The Rijndael affine matrix, as the eight row-bytes GFNI expects packed into a
/// 64-bit lane. Paired with the constant `0x63` it turns `gf2p8affineinv`'s
/// GF(2^8) inversion into the full AES S-box.
const GFNI_SBOX_MATRIX: i64 = 0xF1E3_C78F_1F3E_7CF8_u64 as i64;

/// The affine constant of the Rijndael S-box, i.e. the byte the all-zero input
/// maps to.
const GFNI_SBOX_CONST: i32 = 0x63;

// ==============================================================================
// AES-NI
// ==============================================================================

/// Substitutes all 16 bytes of `x` and XORs `key`, in two instructions.
///
/// Passing a zero `key` gives a plain `SubBytes`; passing the round key folds
/// the cipher's key-mixing step into the same instruction.
#[inline]
#[target_feature(enable = "aes,ssse3")]
unsafe fn sub_bytes_xor_x16_aesni(x: __m128i, key: __m128i) -> __m128i {
    unsafe {
        let mask = _mm_loadu_si128(INV_SHIFT_ROWS.as_ptr() as *const __m128i);
        _mm_aesenclast_si128(_mm_shuffle_epi8(x, mask), key)
    }
}

/// In-place AES S-box over an arbitrary-length slice, 16 bytes at a time.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[target_feature(enable = "aes,ssse3")]
pub unsafe fn sub_bytes_aesni(bytes: &mut [u8]) {
    unsafe {
        let zero = _mm_setzero_si128();
        let mut chunks = bytes.chunks_exact_mut(16);
        for chunk in &mut chunks {
            let p = chunk.as_mut_ptr() as *mut __m128i;
            _mm_storeu_si128(p, sub_bytes_xor_x16_aesni(_mm_loadu_si128(p), zero));
        }
        // A tail shorter than a block is not worth a masked load; the scalar
        // table handles it. `sboxes` (24 bytes) is the only caller that hits it.
        crate::arch::fallback::sub_bytes(chunks.into_remainder());
    }
}

/// One cipher round on AES hardware: rotate right 7, substitute, mix the key.
///
/// After the rotate this is literally two instructions, because `aesenclast`
/// does the substitution and the key XOR together.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[inline]
#[target_feature(enable = "aes,ssse3")]
pub unsafe fn round128_aesni(w: u128, sub_key: u128) -> u128 {
    unsafe {
        let state = _mm_loadu_si128(&w as *const u128 as *const __m128i);
        let key = _mm_loadu_si128(&sub_key as *const u128 as *const __m128i);

        let mixed = sub_bytes_xor_x16_aesni(rotr7_x128(state), key);

        let mut out = 0u128;
        _mm_storeu_si128(&mut out as *mut u128 as *mut __m128i, mixed);
        out
    }
}

/// AES-NI keystream loop.
///
/// The state is held in an XMM register for the whole buffer;
/// [`crate::arch::keystream_core`] inlines into this target-feature context so
/// the round body never spills. See [`super::sbox::fill_keystream_ssse3`] for
/// why the dispatch boundary sits around the buffer rather than the round.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[target_feature(enable = "aes,ssse3")]
pub unsafe fn fill_keystream_aesni(
    w: &mut u128,
    schedule: &[u128],
    round_index: &mut usize,
    out: &mut [u8],
) {
    crate::arch::keystream_core(w, schedule, round_index, out, |state, key| unsafe {
        round128_aesni(state, key)
    });
}

// ==============================================================================
// GFNI
// ==============================================================================

/// Substitutes all 16 bytes of `x` through the AES S-box, in one instruction.
#[inline]
#[target_feature(enable = "gfni")]
unsafe fn sub_bytes_x16_gfni(x: __m128i) -> __m128i {
    _mm_gf2p8affineinv_epi64_epi8::<GFNI_SBOX_CONST>(x, _mm_set1_epi64x(GFNI_SBOX_MATRIX))
}

/// In-place AES S-box over an arbitrary-length slice, 16 bytes at a time.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[target_feature(enable = "gfni")]
pub unsafe fn sub_bytes_gfni(bytes: &mut [u8]) {
    unsafe {
        let mut chunks = bytes.chunks_exact_mut(16);
        for chunk in &mut chunks {
            let p = chunk.as_mut_ptr() as *mut __m128i;
            _mm_storeu_si128(p, sub_bytes_x16_gfni(_mm_loadu_si128(p)));
        }
        crate::arch::fallback::sub_bytes(chunks.into_remainder());
    }
}

/// One cipher round using GFNI: rotate right 7, substitute, mix the key.
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[inline]
#[target_feature(enable = "gfni")]
pub unsafe fn round128_gfni(w: u128, sub_key: u128) -> u128 {
    unsafe {
        let state = _mm_loadu_si128(&w as *const u128 as *const __m128i);
        let key = _mm_loadu_si128(&sub_key as *const u128 as *const __m128i);

        let mixed = _mm_xor_si128(sub_bytes_x16_gfni(rotr7_x128(state)), key);

        let mut out = 0u128;
        _mm_storeu_si128(&mut out as *mut u128 as *mut __m128i, mixed);
        out
    }
}

/// GFNI keystream loop; see [`fill_keystream_aesni`].
///
/// # Safety
///
/// The caller must have established that the host CPU supports the features in
/// this function's `#[target_feature]` list; [`crate::arch`] does that once via
/// `is_x86_feature_detected!` before dispatching here.
#[target_feature(enable = "gfni")]
pub unsafe fn fill_keystream_gfni(
    w: &mut u128,
    schedule: &[u128],
    round_index: &mut usize,
    out: &mut [u8],
) {
    crate::arch::keystream_core(w, schedule, round_index, out, |state, key| unsafe {
        round128_gfni(state, key)
    });
}
