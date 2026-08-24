//! Minimal round-trip example: derive a cipher from a passphrase, encrypt a
//! message, then decrypt it back with a fresh instance using the same key.
//!
//! Run with:
//!   cargo run --example basic_usage

use pich256::pich256::Pich256;

fn main() {
    let key = "correct horse battery staple";
    let message = b"Meet me at the old bridge at midnight.";

    let mut encryptor = Pich256::new(key);
    let ciphertext = encryptor.encrypt(message);

    let mut decryptor = Pich256::new(key);
    let plaintext = decryptor.decrypt(&ciphertext);

    println!("key:        {key}");
    println!("plaintext:  {}", String::from_utf8_lossy(message));
    println!("ciphertext: {}", to_hex(&ciphertext));
    println!("decrypted:  {}", String::from_utf8_lossy(&plaintext));

    assert_eq!(plaintext, message, "round trip failed");
    println!("\nround trip OK");
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
