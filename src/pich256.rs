use crate::bigint::int128::Int128;
use crate::rc::{p, RCS};
use crate::sbox::sbox;

// This struct represents a single "round" of your key schedule.
// sub_key: Int128: This is the actual 128-bit round key material.
// rc: i64: This is the Round Constant. Their primary cryptographic purpose is to break symmetry.
struct Roundkey {
    id: u8,
    sub_key: Int128,
    rc: i64,
}

impl Roundkey {
    pub fn new(id: u8, sub_key: Int128, rc: i64) -> Self {
        Self {
            id,
            sub_key,
            rc,
        }
    }
}

// w: [u8; 16]: This is the 128-bit internal state (16 bytes).
// In a stream cipher, this state is continuously updated. To generate the keystream,
// the cipher will mathematically mix this state,
// sub_keys: This holds the linked list of Roundkeys simply implemented using Vec
struct State{
    w: [u8 ;16],
    sub_keys: Vec<Roundkey>,
}

impl State {
    pub fn new(ke: Int128, w: Int128) -> Self {
        let w_bytes = w.to_be_bytes();

        Self {
            w: w_bytes,
            sub_keys: gensubkeys(ke),
        }
    }

    #[inline]
    pub fn get_round_key(&self, round_index: usize) -> &Roundkey {
        &self.sub_keys[round_index % 16]
    }
}

/// Generates the 16 round keys for the cipher.
pub fn gensubkeys(key: Int128) -> Vec<Roundkey> {
    let mut keys = Vec::with_capacity(16);

    let first_rc = RCS[0] as i64;
    let mut current_subkey = key;

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