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

/// The Rijndael (AES) S-box: a fixed, bijective byte substitution table.
/// Each entry is the multiplicative inverse of the index in GF(2^8) (with 0
/// mapping to itself), followed by an affine transformation over GF(2). This
/// construction is what gives the S-box its non-linearity (confusion) while
/// guaranteeing it is a permutation, so `sbox` never collides two distinct
/// input bytes onto the same output byte.
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// Applies S-box substitution to a single byte
#[inline]
pub fn sbox(byte: u8) -> u8 {
    SBOX[byte as usize]
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // ==============================================================================
    // sbox()
    // ==============================================================================

    #[test]
    fn test_sbox_known_vectors() {
        // Spot-check against the well-known Rijndael S-box values.
        assert_eq!(sbox(0x00), 0x63);
        assert_eq!(sbox(0x01), 0x7c);
        assert_eq!(sbox(0x10), 0xca);
        assert_eq!(sbox(0x53), 0xed);
        assert_eq!(sbox(0x7f), 0xd2);
        assert_eq!(sbox(0xff), 0x16);
    }

    #[test]
    fn test_sbox_is_bijective() {
        // A valid S-box must be a permutation of 0..=255: every input byte
        // maps to a distinct output byte, with full coverage of the range.
        let outputs: HashSet<u8> = (0u8..=255).map(sbox).collect();
        assert_eq!(outputs.len(), 256);
    }

    #[test]
    fn test_sbox_has_no_fixed_points() {
        // Rijndael's S-box is designed so sbox(x) != x and sbox(x) != !x for
        // every x, avoiding trivially predictable substitutions.
        for x in 0u8..=255 {
            assert_ne!(sbox(x), x, "sbox({x:#04x}) should not map to itself");
            assert_ne!(sbox(x), !x, "sbox({x:#04x}) should not map to its complement");
        }
    }

    // ==============================================================================
    // sboxes()
    // ==============================================================================

    #[test]
    fn test_sboxes_applies_to_every_byte() {
        // Give each of the 24 bytes a distinct value so a misplaced or
        // skipped byte would be caught.
        let mut bytes = [0u8; 24];
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = i as u8;
        }
        let input = I192::from_be_bytes(bytes);

        let result = sboxes(input).to_be_bytes();
        for i in 0..24 {
            assert_eq!(result[i], sbox(bytes[i]));
        }
    }

    // ==============================================================================
    // xbox() / cbox()
    // ==============================================================================

    #[test]
    fn test_xbox_zero_extends() {
        let input = Int128::new(-1); // all bits set
        let expanded = xbox(input);

        // Upper 64 bits of the 192-bit value must be zero.
        assert_eq!(expanded.hi(), 0);
        assert_eq!(expanded.mid(), input.hi());
        assert_eq!(expanded.lo(), input.lo());
    }

    #[test]
    fn test_cbox_drops_upper_64_bits() {
        // The hi limb should be ignored entirely by cbox.
        let a = I192::new(0x1234, 10, 20);
        let b = I192::new(-9999, 10, 20);

        assert_eq!(cbox(a), cbox(b));
        assert_eq!(cbox(a), Int128::new((10i128 << 64) | 20u64 as i128));
    }

    #[test]
    fn test_xbox_cbox_round_trip_is_identity() {
        // Since xbox zero-extends and cbox drops exactly that extension,
        // composing them (without the S-box step) should recover the input.
        let input = Int128::new(0x0123456789ABCDEF_FEDCBA9876543210u128 as i128);
        assert_eq!(cbox(xbox(input)), input);
    }

    // ==============================================================================
    // sbox_transform()
    // ==============================================================================

    #[test]
    fn test_sbox_transform_is_bytewise_sbox_on_128_bits() {
        // xbox/sboxes/cbox together are equivalent to substituting each of
        // the 16 big-endian bytes of the 128-bit input independently: the
        // zero-extended high 64 bits get substituted too but are discarded
        // by cbox before they can affect the result.
        let input = Int128::new(0x00112233445566778899AABBCCDDEEFFu128 as i128);

        let mut expected_bytes = input.to_be_bytes();
        for b in expected_bytes.iter_mut() {
            *b = sbox(*b);
        }
        let expected = Int128::from_be_bytes(expected_bytes);

        assert_eq!(sbox_transform(input), expected);
    }

    #[test]
    fn test_sbox_transform_zero() {
        // Every byte of a zero input substitutes to 0x63.
        let expected = Int128::from_be_bytes([0x63; 16]);
        assert_eq!(sbox_transform(Int128::ZERO), expected);
    }

    #[test]
    fn test_sbox_transform_deterministic() {
        let input = Int128::new(0x2f34e5ff91ec85d5_3ca9b5436831744du128 as i128);
        assert_eq!(sbox_transform(input), sbox_transform(input));
    }
}
