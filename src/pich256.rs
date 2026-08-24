use crate::bigint::int128::Int128;

// This struct represents a single "round" of your key schedule.
// sub_key: Int128: This is the actual 128-bit round key material.
// rc: i64: This is the Round Constant. Their primary cryptographic purpose is to break symmetry.
// round_key: Option<Box<Roundkey>>: This makes Roundkey a singly linked list.
struct Roundkey {
    sub_key: Int128,
    rc: i64,
    round_key: Option<Box<Roundkey>>,
}

// w: [u8; 16]: This is the 128-bit internal state (16 bytes).
// In a stream cipher, this state is continuously updated. To generate the keystream,
// the cipher will mathematically mix this state,
// sub_key: Option<Box<Roundkey>>: This holds the linked list of Roundkeys.
struct State{
    w: [u8 ;16],
    sub_key: Option<Box<Roundkey>>,
}