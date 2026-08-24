use crate::bigint::int128::I128;
use crate::kdf::{derive_256bit_key, split_key_into_128bit_limbs};
use crate::key_gen::gen_sub_keys;
use crate::round_key::Roundkey;
use crate::sbox::sbox_transform;

pub struct Pich256{
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
    w: I128,
    sub_keys: Vec<Roundkey>,
    round_index: usize,
}

impl State {
    /// Number of warm-up rounds to ensure proper diffusion of the key
    const WARMUP_ROUNDS: usize = 62;
    // ke: key expansion seed -> low limb of key
    // w: initial state vector (w0) -> high limb of key
    pub fn new(w: I128, ke: I128) -> Self {
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

#[cfg(test)]
mod tests {
    use super::*;

    // ==============================================================================
    // Pich256: encrypt / decrypt round trips
    // ==============================================================================

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let msg = b"The quick brown fox jumps over the lazy dog";

        let mut enc = Pich256::new("correct horse battery staple");
        let ciphertext = enc.encrypt(msg);

        // A fresh instance with the same key must reproduce the same keystream
        // from the start, so it can recover the original plaintext.
        let mut dec = Pich256::new("correct horse battery staple");
        let plaintext = dec.decrypt(&ciphertext);

        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_encrypt_decrypt_round_trip_all_byte_values() {
        // Cover every possible byte value, including 0x00 and 0xff.
        let msg: Vec<u8> = (0..=255u8).collect();

        let mut enc = Pich256::new("key");
        let ciphertext = enc.encrypt(&msg);

        let mut dec = Pich256::new("key");
        let plaintext = dec.decrypt(&ciphertext);

        assert_eq!(plaintext, msg);
    }

    #[test]
    fn test_encrypt_empty_message() {
        let mut cipher = Pich256::new("key");
        assert_eq!(cipher.encrypt(&[]), Vec::<u8>::new());
    }

    #[test]
    fn test_decrypt_empty_message() {
        let mut cipher = Pich256::new("key");
        assert_eq!(cipher.decrypt(&[]), Vec::<u8>::new());
    }

    #[test]
    fn test_encrypt_decrypt_single_byte() {
        let mut enc = Pich256::new("key");
        let ct = enc.encrypt(&[0x42]);
        assert_eq!(ct.len(), 1);

        let mut dec = Pich256::new("key");
        assert_eq!(dec.decrypt(&ct), vec![0x42]);
    }

    #[test]
    fn test_ciphertext_length_matches_plaintext_length() {
        for len in [0, 1, 5, 16, 17, 100, 1000] {
            let msg = vec![0xAB; len];
            let mut cipher = Pich256::new("key");
            assert_eq!(cipher.encrypt(&msg).len(), len);
        }
    }

    #[test]
    fn test_long_message_round_trip() {
        // Long enough to wrap around the round-key schedule (16 keys) and
        // the state's 4-bit byte-selection index many times over.
        let msg: Vec<u8> = (0..10_000u32).map(|i| (i % 256) as u8).collect();

        let mut enc = Pich256::new("long-message-key");
        let ciphertext = enc.encrypt(&msg);

        let mut dec = Pich256::new("long-message-key");
        let plaintext = dec.decrypt(&ciphertext);

        assert_eq!(plaintext, msg);
    }

    // ==============================================================================
    // Pich256: keying edge cases
    // ==============================================================================

    #[test]
    fn test_empty_base_key_does_not_panic() {
        // HMAC-SHA256 accepts a zero-length key, so this must still work.
        let mut cipher = Pich256::new("");
        assert_eq!(cipher.encrypt(b"data").len(), 4);
    }

    #[test]
    fn test_unicode_base_key_round_trips() {
        let key = "pässwörd🔐密码";
        let msg = b"unicode key material";

        let mut enc = Pich256::new(key);
        let ct = enc.encrypt(msg);

        let mut dec = Pich256::new(key);
        assert_eq!(dec.decrypt(&ct), msg);
    }

    // ==============================================================================
    // Pich256: keystream properties
    // ==============================================================================

    #[test]
    fn test_encrypt_is_deterministic_for_same_key_and_message() {
        let msg = b"deterministic";

        let mut a = Pich256::new("same-key");
        let mut b = Pich256::new("same-key");

        assert_eq!(a.encrypt(msg), b.encrypt(msg));
    }

    #[test]
    fn test_different_keys_produce_different_ciphertext() {
        let msg = b"identical plaintext, different keys";

        let mut a = Pich256::new("key-one");
        let mut b = Pich256::new("key-two");

        assert_ne!(a.encrypt(msg), b.encrypt(msg));
    }

    #[test]
    fn test_ciphertext_differs_from_plaintext() {
        let msg = vec![0u8; 64];
        let mut cipher = Pich256::new("key");
        let ct = cipher.encrypt(&msg);

        // Vanishingly unlikely for 64 keystream bytes to all be zero.
        assert_ne!(ct, msg);
    }

    #[test]
    fn test_repeated_encrypt_calls_advance_the_keystream() {
        // Encrypting the same plaintext twice on the *same* instance must not
        // reuse keystream bytes: the internal state advances between calls.
        let msg = b"repeat me";
        let mut cipher = Pich256::new("key");

        let first = cipher.encrypt(msg);
        let second = cipher.encrypt(msg);

        assert_ne!(first, second);
    }

    #[test]
    fn test_decrypt_with_wrong_key_does_not_recover_plaintext() {
        let msg = b"top secret message, do not leak";

        let mut enc = Pich256::new("real-key");
        let ct = enc.encrypt(msg);

        let mut dec = Pich256::new("wrong-key");
        let recovered = dec.decrypt(&ct);

        assert_ne!(recovered, msg);
    }

    // ==============================================================================
    // State: internal round mechanics
    // ==============================================================================

    #[test]
    fn test_state_new_runs_warmup_rounds() {
        let state = State::new(I128::new(1), I128::new(2));

        // round() increments round_index via next_rk(), so after the warmup
        // phase it should sit exactly at WARMUP_ROUNDS.
        assert_eq!(state.round_index, State::WARMUP_ROUNDS);
    }

    #[test]
    fn test_round_mutates_state() {
        let mut state = State::new(I128::new(1), I128::new(2));
        let before = state.w;

        state.round();

        assert_ne!(state.w, before);
    }

    #[test]
    fn test_next_rk_increments_round_index_and_cycles() {
        let mut state = State::new(I128::new(1), I128::new(2));
        let len = state.sub_keys.len();

        let first_id = state.next_rk().id;
        assert_eq!(state.round_index, State::WARMUP_ROUNDS + 1);

        // After exactly `len` total calls, the round-robin schedule must
        // land back on the same round key it started on.
        for _ in 0..len - 1 {
            state.next_rk();
        }
        let wrapped_id = state.next_rk().id;

        assert_eq!(wrapped_id, first_id);
    }

    #[test]
    fn test_get_round_key_wraps_by_modulo() {
        let state = State::new(I128::new(1), I128::new(2));
        let len = state.sub_keys.len();

        assert_eq!(state.get_round_key(0).id, state.get_round_key(len).id);
        assert_eq!(state.get_round_key(1).id, state.get_round_key(len + 1).id);
        assert_eq!(state.get_round_key(0).id, state.get_round_key(len * 3).id);
    }

    #[test]
    fn test_next_byte_matches_two_rounds_then_extract() {
        // next_byte() is documented as: run two rounds, then pull the byte
        // at the index named by the low nibble of the state's first LE byte.
        // Mirror that here against an independently constructed state built
        // from the same key material.
        let mut state = State::new(I128::new(1), I128::new(2));
        let mut expected = State::new(I128::new(1), I128::new(2));
        expected.round();
        expected.round();

        let expected_bytes = expected.w.to_le_bytes();
        let idx = (expected_bytes[0] & 0x0f) as usize;
        let expected_byte = expected_bytes[idx];

        assert_eq!(state.next_byte(), expected_byte);
    }

    #[test]
    fn test_next_byte_many_calls_no_panic() {
        // Exercises every possible 4-bit index (0..=15) over enough calls,
        // and confirms the round counter can advance far past the sub-key
        // schedule length without issue.
        let mut state = State::new(I128::new(42), I128::new(1337));
        for _ in 0..10_000 {
            let _ = state.next_byte();
        }
    }
}