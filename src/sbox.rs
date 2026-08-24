use crate::bigint::int128::Int128;
use crate::bigint::int192::I192;

/// Composition function: sbox_transform(input) = cbox(sboxes(xbox(input)))
/// Expands 128→192, applies S-box substitution, then compresses 192→128
#[inline]
pub fn sbox_transform(input: Int128) -> Int128 {
    let expanded = xbox(input);        // 128 → 192 bits
    let substituted = sboxes(expanded); // Apply S-box to all bytes
    let compressed = cbox(substituted); // 192 → 128 bits
    compressed
}

/// Zero-extends a 128-bit integer to 192 bits
#[inline]
pub fn xbox(input: Int128) -> I192 {
    let hi_128 = input.hi();
    let lo_128 = input.lo();

    // Zero-extend: upper 64 bits of 192-bit value are 0
    I192::new(0, hi_128, lo_128)
}

/// Compresses a 192-bit integer to 128 bits
/// Masks the input to keep only the lower 128 bits
#[inline]
pub fn cbox(input: I192) -> Int128 {
    let mid = input.mid() as i128;
    // Cast to u64 first to prevent sign-extension when converting to i128
    let lo = (input.lo() as u64) as i128;

    // Combine into a single 128-bit integer
    let combined = (mid << 64) | lo;

    Int128::new(combined)
}

/// Applies S-box substitution to a single byte
#[inline]
pub fn sbox(byte: u8) -> u8 {
    // TODO
    byte
}

/// Applies S-box substitution to all 24 bytes of a 192-bit integer
pub fn sboxes(input: I192) -> I192 {
    let bytes = input.to_be_bytes();

    // Apply S-box to each byte
    let mut substituted = [0u8; 24];
    for i in 0..24 {
        substituted[i] = sbox(bytes[i]);
    }

    I192::from_be_bytes(substituted)
}
