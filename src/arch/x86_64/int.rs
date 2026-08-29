//! 128-bit integer primitives written as x86_64 inline assembly.
//!
//! A 128-bit value lives in a *pair* of 64-bit registers on x86_64, so every
//! operation on it is a small multi-instruction sequence. The hardware has
//! dedicated instructions for exactly these sequences:
//!
//! * `shld` / `shrd` - "double precision shift": shift one register while
//!   feeding in the bits spilling out of a second one. A 128-bit rotate is two
//!   of them.
//! * `mul` / `imul` - the one-operand `mul r64` form produces a full 128-bit
//!   product in `rdx:rax`, which is the wide partial product a truncating
//!   128x128 multiply is built from.
//!
//! LLVM already lowers `u128::rotate_right` and `u128::wrapping_mul` to these
//! same instructions, so this module is not expected to *beat* the compiler. It
//! exists because the operations are architecture-specific by nature and the
//! project wants them spelled out explicitly, and because it pins the codegen:
//! the sequence cannot silently regress into a call to `__multi3` or a branchy
//! shift when inlining decisions change.
//!
//! # Safety
//!
//! Every block is `nomem` (touches no memory), `nostack` (pushes nothing), and
//! `pure` (same inputs always give the same outputs, no side effects), which
//! lets the optimiser hoist and CSE them like ordinary arithmetic. Flags *are*
//! clobbered - `preserves_flags` is deliberately not set, because `shld`,
//! `shrd`, `add` and `mul` all write EFLAGS.

use core::arch::asm;

/// Rotates a 128-bit value left by `n` bits.
///
/// `n` is reduced modulo 128. A rotate of 64 or more is turned into a swap of
/// the two halves plus a shorter rotate, because `shld`'s count operand is taken
/// modulo 64 by the hardware and cannot express the wider case on its own.
#[inline]
pub fn rotl128(x: u128, n: u32) -> u128 {
    let n = n & 127;
    let (mut lo, mut hi) = (x as u64, (x >> 64) as u64);
    if n >= 64 {
        core::mem::swap(&mut lo, &mut hi);
    }
    let count = n & 63;

    unsafe {
        asm!(
            // Keep the original high half: the second shift needs the bits that
            // the first one is about to overwrite.
            "mov  {tmp}, {hi}",
            // hi = (hi << cl) | (lo >> (64 - cl))
            "shld {hi}, {lo}, cl",
            // lo = (lo << cl) | (hi_original >> (64 - cl))
            "shld {lo}, {tmp}, cl",
            lo = inout(reg) lo,
            hi = inout(reg) hi,
            tmp = out(reg) _,
            // `shld`'s variable count operand is architecturally CL.
            in("ecx") count,
            options(pure, nomem, nostack),
        );
    }

    ((hi as u128) << 64) | lo as u128
}

/// Rotates a 128-bit value right by `n` bits. Mirror image of [`rotl128`].
#[inline]
pub fn rotr128(x: u128, n: u32) -> u128 {
    let n = n & 127;
    let (mut lo, mut hi) = (x as u64, (x >> 64) as u64);
    if n >= 64 {
        core::mem::swap(&mut lo, &mut hi);
    }
    let count = n & 63;

    unsafe {
        asm!(
            "mov  {tmp}, {lo}",
            // lo = (lo >> cl) | (hi << (64 - cl))
            "shrd {lo}, {hi}, cl",
            // hi = (hi >> cl) | (lo_original << (64 - cl))
            "shrd {hi}, {tmp}, cl",
            lo = inout(reg) lo,
            hi = inout(reg) hi,
            tmp = out(reg) _,
            in("ecx") count,
            options(pure, nomem, nostack),
        );
    }

    ((hi as u128) << 64) | lo as u128
}

/// Truncating (wrapping) 128x128 -> low 128 bit multiplication.
///
/// Writing `a = a_hi*2^64 + a_lo` and `b = b_hi*2^64 + b_lo`, the full product is
///
/// ```text
/// a*b = a_hi*b_hi * 2^128  +  (a_hi*b_lo + a_lo*b_hi) * 2^64  +  a_lo*b_lo
/// ```
///
/// The `a_hi*b_hi` term lands entirely above bit 127 and is discarded, and only
/// the low 64 bits of the two cross terms survive, so the whole thing is one
/// widening `mul` plus two narrow `imul`s:
///
/// ```text
/// rdx:rax = a_lo * b_lo
/// result  = ((rdx + a_hi*b_lo + a_lo*b_hi) << 64) | rax
/// ```
#[inline]
pub fn mul128(a: u128, b: u128) -> u128 {
    let (a_lo, a_hi) = (a as u64, (a >> 64) as u64);
    let (b_lo, b_hi) = (b as u64, (b >> 64) as u64);

    let out_lo: u64;
    let out_hi: u64;

    unsafe {
        asm!(
            // rdx:rax = rax * b_lo, with rax pre-loaded with a_lo.
            "mul  {b_lo}",
            // cross1 = a_hi * b_lo   (two-operand imul keeps only the low 64 bits)
            "imul {cross1}, {b_lo}",
            // cross2 = a_lo * b_hi
            "imul {cross2}, {b_hi}",
            "add  rdx, {cross1}",
            "add  rdx, {cross2}",
            b_lo = in(reg) b_lo,
            b_hi = in(reg) b_hi,
            cross1 = inout(reg) a_hi => _,
            cross2 = inout(reg) a_lo => _,
            // `mul r64` is hard-wired to rax as its second factor and rdx:rax as
            // its destination; naming them explicitly keeps the register
            // allocator from handing them out for the `reg` operands above.
            inout("rax") a_lo => out_lo,
            out("rdx") out_hi,
            options(pure, nomem, nostack),
        );
    }

    ((out_hi as u128) << 64) | out_lo as u128
}
