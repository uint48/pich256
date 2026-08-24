//! Small CLI wrapper around Pich256: encrypts a message given on the command
//! line and prints the ciphertext as hex.
//!
//! Run with:
//!   cargo run --example cli_encrypt -- "my passphrase" "attack at dawn"

use pich256::pich256::Pich256;
use std::env;
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();

    let [_, key, message] = args.as_slice() else {
        eprintln!("Usage: cli_encrypt <key> <message>");
        process::exit(1);
    };

    let mut cipher = Pich256::new(key);
    let ciphertext = cipher.encrypt(message.as_bytes());

    println!("{}", to_hex(&ciphertext));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
