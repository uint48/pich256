use crate::arch;
use crate::bigint::int128::I128;
use crate::rc::{p, RCS};
use crate::round_key::Roundkey;
use crate::sbox::sbox;

/// Generates the 16 round keys for the cipher.
pub fn gen_sub_keys(ke: I128) -> Vec<Roundkey> {
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
//
// The rotates and the 128-bit multiply go through `crate::arch` so that on
// x86_64 they compile to the dedicated `shld`/`shrd` double-precision shifts and
// the `mul`/`imul` widening-product sequence written out in
// `arch::x86_64::int`. The single-byte S-box stays a scalar table lookup: it is
// one byte of *key schedule* material, evaluated 15 times at construction, so
// there is nothing to vectorise.
#[inline]
pub fn g(x: I128, rc: i64) -> I128 {
    // y = rotl(x, 7);
    let mut y = arch::rotl128(x.0 as u128, 7);

    // y = y * rc;
    y = arch::mul128(y, rc as i128 as u128);

    // y = rotr(y, 4);
    y = arch::rotr128(y, 4);

    // Byte manipulation
    let mut bytes = y.to_le_bytes();

    // Apply the S-box to the byte at offset 14
    bytes[14] = sbox(bytes[14]);

    y = u128::from_le_bytes(bytes);

    // y = rotl(y, 4);
    y = arch::rotl128(y, 4);

    I128::new(y as i128)
}