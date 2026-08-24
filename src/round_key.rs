use crate::bigint::int128::Int128;

// This struct represents a single "round" of your key schedule.
// sub_key: Int128: This is the actual 128-bit round key material.
// rc: i64: This is the Round Constant. Their primary cryptographic purpose is to break symmetry.
pub struct Roundkey {
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
