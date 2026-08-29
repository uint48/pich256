//! x86_64 backends.
//!
//! Everything in here is selected at **runtime** by [`crate::arch::backend`],
//! which probes the host CPU with `is_x86_feature_detected!` exactly once and
//! caches the answer. The crate therefore stays portable to any x86_64 machine:
//! a binary built on an AVX-512 host still runs correctly on an SSE2-only host.
//!
//! # Feature ladder
//!
//! | Backend      | Requires                                | S-box strategy                      |
//! |--------------|-----------------------------------------|-------------------------------------|
//! | `Avx512Vbmi` | `avx512f avx512bw avx512vl avx512vbmi`  | 2x `vpermi2b` over a 256-byte table |
//! | `Avx2`       | `avx2`                                  | 16x `vpshufb` on 32 bytes at a time |
//! | `Ssse3`      | `ssse3`                                 | 16x `pshufb` on 16 bytes at a time  |
//! | `Sse2`       | x86_64 baseline                         | scalar table lookup                 |
//!
//! # Deliberately unused instructions
//!
//! * **AES-NI** (`aesenclast`) computes AES `SubBytes` + `ShiftRows` in a single
//!   instruction and would make the S-box nearly free. It is *not* used here:
//!   Pich256 is meant to stand on its own primitives, not on an AES core.
//! * **GFNI** (`vgf2p8affineinvqb`) is a general Galois-field instruction, but
//!   with the Rijndael affine constant it is literally the AES S-box in one
//!   instruction. It is left out for the same reason, even though the detection
//!   code reports whether the host has it.
//!
//! Both are easy to slot in later as extra `Backend` variants.

/// Inline-assembly 128-bit integer primitives. Gated on `asm` rather than
/// `simd`: they are independent of the vector backends and can be enabled or
/// disabled on their own.
#[cfg(feature = "asm")]
pub mod int;

#[cfg(feature = "simd")]
pub mod sbox;

#[cfg(feature = "simd")]
pub mod sha;
