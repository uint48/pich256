use crate::bigint::int128::Int128;
use crate::rc::{p, RCS};
use crate::round_key::Roundkey;
use crate::sbox::sbox;

/// Generates the 16 round keys for the cipher.
pub fn gen_sub_keys(ke: Int128) -> Vec<Roundkey> {
    let mut keys = Vec::with_capacity(16);

    let first_rc = RCS[0] as i64;
    let mut current_subkey = ke;

    keys.push(Roundkey::new(0, current_subkey, first_rc));

    // x = 1 to 15
    for x in 1..16 {
        let rc = p(RCS[x as usize]);
        current_subkey = g(current_subkey, rc);
        keys.push(Roundkey::new(x, current_subkey, rc));
    }

    keys
}

// key mixing function that generates the next subkey
// Subkey Generator Function
#[inline]
pub fn g(x: Int128, rc: i64) -> Int128 {
    // y = rotl(x, 7);
    let mut y = x.rotate_left(7);

    // y = y * rc;
    y = y * Int128::new(rc as i128);

    // y = rotr(y, 4);
    y = y.rotate_right(4);

    // Byte manipulation
    let mut bytes = y.to_le_bytes();

    // Apply the S-box to the byte at offset 14
    bytes[14] = sbox(bytes[14]);

    y = Int128::from_le_bytes(bytes);

    // y = rotl(y, 4);
    y = y.rotate_left(4);

    y
}