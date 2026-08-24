// ==============================================================================
// 256-bit Key Derivation
// ==============================================================================

use crate::bigint::int128::I128;
use crate::bigint::int256::I256;
use crate::sha256::hmac_sha256;

pub fn derive_256bit_key(key: &[u8]) -> I256 {
    let default_salt = [0u8; 32];

    let prk = hmac_sha256(&default_salt, key);
    let okm = hmac_sha256(&prk, &[0x01]);

    // Convert the 32-byte output into two 16-byte halves (big-endian)
    let hi = i128::from_be_bytes(okm[0..16].try_into().unwrap());
    let lo = i128::from_be_bytes(okm[16..32].try_into().unwrap());

    I256::new(hi, lo)
}

pub fn split_key_into_128bit_limbs(key: &I256) -> (I128, I128) {
    (
        I128::new(key.hi()),
        I128::new(key.lo()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to convert a byte slice to a hex string
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // ==============================================================================
    // 256-bit Key Derivation Tests
    // ==============================================================================

    #[test]
    fn test_derive_256bit_key_length() {
        let secret = b"my_super_secret_password";
        let key = derive_256bit_key(secret);

        // Guarantee: I256 inherently represents exactly 32 bytes (256 bits)
        // composed of two 128-bit parts.
        let _ = key.hi();
        let _ = key.lo();
    }

    #[test]
    fn test_derive_256bit_key_deterministic() {
        let secret = b"secret";
        let key1 = derive_256bit_key(secret);
        let key2 = derive_256bit_key(secret);

        // Guarantee: Same input must always produce the exact same output
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_derive_256bit_key_known_vector() {
        let secret = b"secret";
        let key = derive_256bit_key(secret);

        // Convert I256 back to a 32-byte array to verify against the expected hex string
        let hi_bytes = key.hi().to_be_bytes();
        let lo_bytes = key.lo().to_be_bytes();
        let mut key_bytes = [0u8; 32];
        key_bytes[0..16].copy_from_slice(&hi_bytes);
        key_bytes[16..32].copy_from_slice(&lo_bytes);

        // Expected output derived from:
        // 1. PRK = HMAC-SHA256([0u8; 32], "secret")
        // 2. OKM = HMAC-SHA256(PRK, &[0x01])
        let expected = "2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf";
        assert_eq!(bytes_to_hex(&key_bytes), expected);
    }

    #[test]
    fn test_split_key_128bit_limbs() {
        // Create a predictable I256 key
        // Using 16 bytes of 0xAA for the first half, and 16 bytes of 0xBB for the second half
        let hi_val = i128::from_be_bytes([0xAA; 16]);
        let lo_val = i128::from_be_bytes([0xBB; 16]);

        let key = I256::new(hi_val, lo_val);

        // Note: 'lower' and 'higher' naming is preserved from the original test
        // to represent the first half (index 0..16) and second half (index 16..32) respectively.
        let (lower, higher) = split_key_into_128bit_limbs(&key);

        assert_eq!(lower, I128::new(hi_val));
        assert_eq!(higher, I128::new(lo_val));
    }
}