//! Portable software implementations of every accelerated primitive.
//!
//! This module compiles on **every** target. It serves two purposes:
//!
//! 1. It is the implementation actually used on architectures that have no
//!    hand-written backend yet (aarch64, riscv64, wasm32, ...), and on x86_64
//!    when the `simd`/`asm` features are switched off.
//! 2. It is the *reference oracle*: the unit tests in [`crate::arch`] run every
//!    architecture-specific backend against these functions, so a backend that
//!    disagrees with the portable code fails the build's test suite.
//!
//! Nothing here may use `core::arch`, inline assembly, or any CPU feature
//! beyond what the base target guarantees.

use crate::sbox::SBOX;

/// Applies the AES S-box to every byte of `bytes`, in place.
///
/// Note that this is a *table lookup*, so it is not constant-time with respect
/// to the data: the index into `SBOX` is secret-dependent and therefore leaks
/// through the data cache. The x86_64 vector backends do not have this problem
/// because they never index memory with secret data.
#[inline]
pub fn sub_bytes(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        *b = SBOX[*b as usize];
    }
}

/// One full cipher round: `rotate_right(7)`, bytewise S-box, then key mixing.
///
/// Kept as a single function (rather than three composable ones) because the
/// vector backends keep the state resident in one register across all three
/// steps; see [`crate::arch::round128`].
#[inline]
pub fn round128(w: u128, sub_key: u128) -> u128 {
    // Diffusion.
    let rotated = w.rotate_right(7);

    // Confusion. The substitution is bytewise, so it does not matter whether
    // the state is decomposed into little- or big-endian bytes here, as long as
    // the same order is used to put it back together.
    let mut bytes = rotated.to_le_bytes();
    sub_bytes(&mut bytes);

    // Key mixing.
    u128::from_le_bytes(bytes) ^ sub_key
}

/// Rotates a 128-bit value left by `n` bits.
#[inline]
pub fn rotl128(x: u128, n: u32) -> u128 {
    x.rotate_left(n)
}

/// Rotates a 128-bit value right by `n` bits.
#[inline]
pub fn rotr128(x: u128, n: u32) -> u128 {
    x.rotate_right(n)
}

/// Truncating (wrapping) 128x128 -> low 128 bit multiplication.
#[inline]
pub fn mul128(a: u128, b: u128) -> u128 {
    a.wrapping_mul(b)
}

/// `dst[i] ^= src[i]` for the whole overlap of the two slices.
#[inline]
pub fn xor_into(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= *s;
    }
}

// ==============================================================================
// SHA-256 block compression (FIPS 180-4, section 6.2.2)
// ==============================================================================

pub(crate) const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Compresses one or more already-padded 64-byte blocks into `state`.
///
/// `blocks.len()` must be a non-zero multiple of 64; the caller
/// ([`crate::sha256::sha256`]) is responsible for the padding.
pub fn sha256_compress(state: &mut [u32; 8], blocks: &[u8]) {
    debug_assert_eq!(blocks.len() % 64, 0);

    for chunk in blocks.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16]
                .wrapping_add(s0)
                .wrapping_add(w[i - 7])
                .wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h) = (
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        );

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(SHA256_K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        state[0] = state[0].wrapping_add(a);
        state[1] = state[1].wrapping_add(b);
        state[2] = state[2].wrapping_add(c);
        state[3] = state[3].wrapping_add(d);
        state[4] = state[4].wrapping_add(e);
        state[5] = state[5].wrapping_add(f);
        state[6] = state[6].wrapping_add(g);
        state[7] = state[7].wrapping_add(h);
    }
}
