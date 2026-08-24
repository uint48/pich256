use crate::bigint::int128::I128;

// This struct represents a single "round" of your key schedule.
// sub_key: Int128: This is the actual 128-bit round key material.
// rc: i64: This is the Round Constant. Their primary cryptographic purpose is to break symmetry.
pub struct Roundkey {
    pub id: u8,
    pub sub_key: I128,
    pub rc: i64,
}

impl Roundkey {
    pub fn new(id: u8, sub_key: I128, rc: i64) -> Self {
        Self {
            id,
            sub_key,
            rc,
        }
    }
}
