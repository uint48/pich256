// ==============================================================================
// SHA-256 (FIPS 180-4)
// ==============================================================================
//
// Padding and length encoding live here; the per-block compression function is
// dispatched through `crate::arch` so it can use the Intel SHA extensions
// (`sha256rnds2` / `sha256msg1` / `sha256msg2`) when the host has them, and the
// portable loop in `arch::fallback` otherwise.

use crate::arch;

/// The eight initial hash values H(0), the first 32 bits of the fractional parts
/// of the square roots of the first eight primes.
const SHA256_IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut msg = data.to_vec();
    let orig_len = msg.len();

    // Pre-processing: append 0x80, then zeros until the length is 56 mod 64, so
    // that the 8-byte bit length lands exactly on a block boundary.
    msg.push(0x80);
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }
    let bit_len = (orig_len as u64) * 8;
    msg.extend_from_slice(&bit_len.to_be_bytes());

    let mut h = SHA256_IV;
    arch::sha256_compress(&mut h, &msg);

    // Produce the final 256-bit (32-byte) hash value
    let mut result = [0u8; 32];
    for i in 0..8 {
        result[i * 4..(i + 1) * 4].copy_from_slice(&h[i].to_be_bytes());
    }
    result
}

// ==============================================================================
// HMAC-SHA256 Pure Software Implementation (RFC 2104)
// ==============================================================================

pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let block_size = 64;

    // If key is longer than block size, hash it. Otherwise, pad with zeros.
    let mut key = if key.len() > block_size {
        sha256(key).to_vec()
    } else {
        key.to_vec()
    };
    key.resize(block_size, 0);

    let mut i_key_pad = vec![0u8; block_size];
    let mut o_key_pad = vec![0u8; block_size];
    for i in 0..block_size {
        i_key_pad[i] = key[i] ^ 0x36;
        o_key_pad[i] = key[i] ^ 0x5c;
    }

    // Inner hash
    let mut inner_data = i_key_pad;
    inner_data.extend_from_slice(data);
    let inner_hash = sha256(&inner_data);

    // Outer hash
    let mut outer_data = o_key_pad;
    outer_data.extend_from_slice(&inner_hash);
    sha256(&outer_data)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper function to convert a hex string to a byte vector
    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        assert_eq!(hex.len() % 2, 0, "Hex string must have an even length");
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    // Helper function to convert a byte slice to a hex string
    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    // ==============================================================================
    // SHA-256 Tests (FIPS 180-4 Test Vectors)
    // ==============================================================================

    #[test]
    fn test_sha256_empty() {
        let data = b"";
        let expected = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let result = sha256(data);
        assert_eq!(bytes_to_hex(&result), expected);
    }

    #[test]
    fn test_sha256_abc() {
        let data = b"abc";
        let expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        let result = sha256(data);
        assert_eq!(bytes_to_hex(&result), expected);
    }

    #[test]
    fn test_sha256_long_message() {
        let data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
        let expected = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";
        let result = sha256(data);
        assert_eq!(bytes_to_hex(&result), expected);
    }

    // ==============================================================================
    // HMAC-SHA256 Tests (RFC 4231 Test Vectors)
    // ==============================================================================

    #[test]
    fn test_hmac_sha256_rfc4231_case1() {
        let key = hex_to_bytes("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        let data = hex_to_bytes("4869205468657265"); // "Hi There"
        let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

        let result = hmac_sha256(&key, &data);
        assert_eq!(bytes_to_hex(&result), expected);
    }

    #[test]
    fn test_hmac_sha256_rfc4231_case2() {
        let key = hex_to_bytes("4a656665"); // "Jefe"
        let data = hex_to_bytes("7768617420646f2079612077616e7420666f72206e6f7468696e673f"); // "what do ya want for nothing?"
        let expected = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843";

        let result = hmac_sha256(&key, &data);
        assert_eq!(bytes_to_hex(&result), expected);
    }


}