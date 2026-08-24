// ==============================================================================
// 256-bit Key Derivation
// ==============================================================================

use crate::sha256::hmac_sha256;

pub fn derive_256bit_key(secret: &[u8]) -> [u8; 32] {
    let default_salt = [0u8; 32];

    let prk = hmac_sha256(&default_salt, secret);

    hmac_sha256(&prk, &[0x01])
}

pub fn split_key_into_128bit_limbs(key: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    (
        key[0..16].try_into().unwrap(),
        key[16..32].try_into().unwrap(),
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

        // Guarantee: Always returns exactly 32 bytes (256 bits)
        assert_eq!(key.len(), 32);
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

        // Expected output derived from:
        // 1. PRK = HMAC-SHA256([0u8; 32], "secret")
        // 2. OKM = HMAC-SHA256(PRK, &[0x01])
        let expected = "2f34e5ff91ec85d53ca9b543683174d0cf550b60d5f52b24c97b386cfcf6cbbf";
        assert_eq!(bytes_to_hex(&key), expected);
    }

    #[test]
    fn test_split_key_128bit_limbs() {
        // Create a predictable 32-byte key
        let mut key = [0u8; 32];
        key[0..16].copy_from_slice(&[0xAA; 16]); // First half
        key[16..32].copy_from_slice(&[0xBB; 16]); // Second half

        let (lower, higher) = split_key_into_128bit_limbs(&key);

        assert_eq!(lower, [0xAA; 16]);
        assert_eq!(higher, [0xBB; 16]);
    }

}