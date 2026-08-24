use crate::bigint::int128::Int128;
use crate::key_gen::gen_sub_keys;
use crate::round_key::Roundkey;



// w: [u8; 16]: This is the 128-bit internal state (16 bytes).
// In a stream cipher, this state is continuously updated. To generate the keystream,
// the cipher will mathematically mix this state,
// sub_keys: This holds the linked list of Roundkeys simply implemented using Vec
struct State{
    w: [u8 ;16],
    sub_keys: Vec<Roundkey>,
}

impl State {
    // ke: key expansion seed -> low limb of key
    // w: initial state vector (w0) -> high limb of key
    pub fn new(w: Int128, ke: Int128) -> Self {
        let w_bytes = w.to_be_bytes();

        Self {
            w: w_bytes,
            sub_keys: gen_sub_keys(ke),
        }
    }

    #[inline]
    pub fn get_round_key(&self, round_index: usize) -> &Roundkey {
        &self.sub_keys[round_index % 16]
    }
}