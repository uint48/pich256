//! Demonstrates the avalanche effect: encrypting the exact same message with
//! two keys that differ by a single character produces wildly different
//! ciphertext.
//!
//! Run with:
//!   cargo run --example key_sensitivity

// Output:
// key A: "password123"
// key B: "password124"  (one character different)
//
// ciphertext A: b5cdd54668cdc70e0390e3caad0855f4d565d9842c55fcb27a7b5821b4b433231dad5903a84044d2
// ciphertext B: c97e1bff1b08a22c1ebfa332f90fc719d6ecec0484c43b25c7b01191afa76884cecc3ac54b92d068
//
// 40/40 bytes differ, 158/320 bits differ


use pich256::pich256::Pich256;

fn main() {
    let message = b"The exact same message, encrypted twice.";
    let key_a = "password123";
    let key_b = "password124"; // one character different

    let mut a = Pich256::new(key_a);
    let mut b = Pich256::new(key_b);

    let ciphertext_a = a.encrypt(message);
    let ciphertext_b = b.encrypt(message);

    let differing_bytes = ciphertext_a
        .iter()
        .zip(ciphertext_b.iter())
        .filter(|(x, y)| x != y)
        .count();

    let differing_bits: u32 = ciphertext_a
        .iter()
        .zip(ciphertext_b.iter())
        .map(|(x, y)| (x ^ y).count_ones())
        .sum();

    println!("key A: {key_a:?}");
    println!("key B: {key_b:?}  (one character different)\n");
    println!("ciphertext A: {}", to_hex(&ciphertext_a));
    println!("ciphertext B: {}", to_hex(&ciphertext_b));
    println!(
        "\n{differing_bytes}/{} bytes differ, {differing_bits}/{} bits differ",
        ciphertext_a.len(),
        ciphertext_a.len() * 8
    );
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
