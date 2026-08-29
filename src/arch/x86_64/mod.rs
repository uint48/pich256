//! x86_64 backends.
//!
//! Everything in here is selected at **runtime** by [`crate::arch::backend`],
//! which probes the host CPU with `is_x86_feature_detected!` exactly once and
//! caches the answer. The crate therefore stays portable to any x86_64 machine:
//! a binary built on an AVX-512 host still runs correctly on an SSE2-only host.
//!
//! # Feature ladder
//!
//! | Backend      | Requires                                | S-box strategy                       |
//! |--------------|-----------------------------------------|--------------------------------------|
//! | `AesNi`      | `aes ssse3`                             | `pshufb` + `aesenclast`, key XOR free |
//! | `Gfni`       | `gfni`                                  | one `gf2p8affineinv`                 |
//! | `Avx512Vbmi` | `avx512f avx512bw avx512vl avx512vbmi`  | 2x `vpermi2b` over a 256-byte table  |
//! | `Avx2`       | `avx2`                                  | 8x `vpshufb`, two rows per register  |
//! | `Ssse3`      | `ssse3`                                 | 16x `pshufb`, one row per register   |
//! | `Sse2`       | x86_64 baseline                         | scalar table lookup                  |
//!
//! Pich256's confusion layer is the Rijndael S-box, so on any CPU with AES
//! hardware the substitution is available directly - see [`aes`]. The shuffle
//! backends in [`sbox`] emulate the same 256-entry table out of 16-entry byte
//! shuffles, and exist for CPUs without AES-NI or GFNI. They are roughly 3x
//! slower end to end, but they are constant-time, which the scalar table in
//! `arch::fallback` is not.
//!
//! The two hardware paths differ in what they fold in: `aesenclast` performs
//! `SubBytes(ShiftRows(x)) XOR k`, so cancelling its `ShiftRows` with one
//! `pshufb` yields the substitution *and* the round's key mixing in two
//! instructions, whereas `gf2p8affineinv` gives a bare `SubBytes` in one
//! instruction and needs a separate `pxor`. On the hardware this was developed
//! on the AES-NI form wins, so it is the one the detector prefers; the reasoning
//! is spelled out in `arch::detect`.

pub mod int;

#[cfg(feature = "simd")]
pub mod aes;

#[cfg(feature = "simd")]
pub mod sbox;

#[cfg(feature = "simd")]
pub mod sha;
