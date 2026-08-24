use crate::bigint::int128::Int128;
use crate::sbox::{cbox, sboxes, xbox};

/// Composition function: f(input) = cbox(sboxes(xbox(input)))
/// Expands 128→192, applies S-box substitution, then compresses 192→128
#[inline]
pub fn f(input: Int128) -> Int128 {
    let expanded = xbox(input);        // 128 → 192 bits
    let substituted = sboxes(expanded); // Apply S-box to all bytes
    let compressed = cbox(substituted); // 192 → 128 bits
    compressed
}