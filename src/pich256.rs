use crate::bigint::int128::Int128;
use crate::kdf::{derive_256bit_key, split_key_into_128bit_limbs};
use crate::key_gen::gen_sub_keys;
use crate::round_key::Roundkey;
use crate::sbox::sbox_transform;

struct Pich256{
    st: State
}

impl Pich256 {
    pub fn new(base_key: &str) -> Self{
        // Convert the string to a byte slice and derive the 256-bit key
        let derived_key = derive_256bit_key(base_key.as_bytes());

        // Split the I256 key into two Int128 limbs
        let (key_hi, key_lo) = split_key_into_128bit_limbs(&derived_key);

        Self {
            st: State::new(key_hi, key_lo),
        }
    }
    #[inline]
    pub fn encrypt(&mut self, msg: &[u8]) -> Vec<u8> {
        let mut ciphertext = Vec::with_capacity(msg.len());
        for &byte in msg {
            // XOR each plaintext byte with the next keystream byte
            ciphertext.push(byte ^ self.st.next_byte());
        }
        ciphertext
    }

    #[inline]
    pub fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());
        for &byte in ciphertext {
            plaintext.push(byte ^ self.st.next_byte());
        }
        plaintext
    }
}

// w: Int128: This is the 128-bit internal state (16 bytes).
// In a stream cipher, this state is continuously updated. To generate the keystream,
// the cipher will mathematically mix this state,
// sub_keys: This holds the linked list of Roundkeys simply implemented using Vec
struct State{
    w: Int128,
    sub_keys: Vec<Roundkey>,
    round_index: usize,
}

impl State {
    /// Number of warm-up rounds to ensure proper diffusion of the key
    const WARMUP_ROUNDS: usize = 62;
    // ke: key expansion seed -> low limb of key
    // w: initial state vector (w0) -> high limb of key
    pub fn new(w: Int128, ke: Int128) -> Self {
        let mut state = Self {
            w,
            sub_keys: gen_sub_keys(ke),
            round_index: 0,
        };

        // WARM-UP PHASE
        // ensures full entropy diffusion before any keystream is generated.
        for _ in 0..Self::WARMUP_ROUNDS {
            state.round();
        }
        // the initial 128-bit state is rotated, substituted, and key-mixed 62 times in a row.
        // By the end of it, the original key material is so thoroughly blended and scrambled
        // that the resulting state is indistinguishable from pure random noise,
        // making it perfectly safe to use as a keystream generator.

        state
    }

    #[inline]
    pub fn next_rk(&mut self) -> &Roundkey {
        let len = self.sub_keys.len();
        let rk = &self.sub_keys[self.round_index % len];

        // Use wrapping_add to prevent panic on overflow if the
        // stream cipher runs for a massively long time (usize::MAX rounds).
        self.round_index = self.round_index.wrapping_add(1);
        rk
    }

    // In cryptography, a round function is the repeating mathematical operation
    // that scrambles the internal state to achieve confusion and diffusion
    // (the two fundamental principles of secure encryption defined by Claude Shannon).
    #[inline]
    pub fn round(&mut self) {
        let sub_key = self.next_rk().sub_key;

        // Rotation (Diffusion)
        self.w = self.w.rotate_right(7);
        // S-Box Transformation (Confusion)
        self.w = sbox_transform(self.w);
        // Key Mixing (XOR)
        self.w = self.w ^ sub_key;
    }

    // Keystream generator, produce a single, pseudo-random byte that will be XORed with
    // your plaintext (to encrypt) or ciphertext (to decrypt)
    #[inline]
    pub fn next_byte(&mut self) -> u8 {
        // This guarantees that the byte you are about to extract
        // is thoroughly mixed and unpredictable.
        self.round();
        self.round();

        let w_bytes = self.w.to_le_bytes();

        // The result of anything & 0x0f is guaranteed to be a number between 0 and 15.
        // Since our state byte array has exactly 16 elements
        let idx = (w_bytes[0] & 0x0f) as usize;

        w_bytes[idx]
    }


    #[inline]
    pub fn get_round_key(&self, round_index: usize) -> &Roundkey {
        &self.sub_keys[round_index % self.sub_keys.len()]
    }
}