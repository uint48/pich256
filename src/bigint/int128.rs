use std::fmt;
use std::ops::{Add, BitAnd, BitOr, BitXor, BitXorAssign, Mul, Neg, Not, Sub};


/// In Rust, you actually already have a native,
/// highly optimized i128 (and u128) type built directly into the language.
/// A newtype wrapper around the native `i128` type.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Int128(pub i128);

impl fmt::Debug for Int128 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Int128({})", self.0)
    }
}

impl Int128 {
    /// The additive identity, i.e. `0`.
    pub const ZERO: Self = Self(0);

    /// The multiplicative identity, i.e. `1`.
    pub const ONE: Self = Self(1);

    /// The multiplicative inverse, i.e. `-1`.
    pub const MINUS_ONE: Self = Self(-1);

    #[inline]
    pub const fn new(val: i128) -> Self {
        Self(val)
    }

    #[inline]
    pub const fn lo(&self) -> i64 {
        (self.0 & 0xFFFFFFFFFFFFFFFF) as i64
    }

    #[inline]
    pub const fn hi(&self) -> i64 {
        (self.0 >> 64) as i64
    }

    /// Shifts the bits to the left by a specified amount, `n`,
    #[inline]
    pub const fn rotate_left(self, n: u32) -> Self {
        Self(self.0.rotate_left(n))
    }

    /// Shifts the bits to the right by a specified amount, `n`,
    #[inline]
    pub const fn rotate_right(self, n: u32) -> Self {
        Self(self.0.rotate_right(n))
    }

    /// Converts the integer to a 16-byte array in big-endian order.
    #[inline]
    pub fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    /// Creates a new integer from a 16-byte array in big-endian order.
    #[inline]
    pub fn from_be_bytes(bytes: [u8; 16]) -> Self {
        Self(i128::from_be_bytes(bytes))
    }

    /// Converts the integer to a 16-byte array in little-endian order.
    #[inline]
    pub fn to_le_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// Creates a new integer from a 16-byte array in little-endian order.
    #[inline]
    pub fn from_le_bytes(bytes: [u8; 16]) -> Self {
        Self(i128::from_le_bytes(bytes))
    }
}

impl Add for Int128 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_add(rhs.0))
    }
}

impl Sub for Int128 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_sub(rhs.0))
    }
}

impl Mul for Int128 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.wrapping_mul(rhs.0))
    }
}

impl Neg for Int128 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output {
        Self(self.0.wrapping_neg())
    }
}

impl BitXor for Int128 {
    type Output = Self;
    #[inline]
    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Int128 {
    #[inline]
    fn bitxor_assign(&mut self, rhs: Self) {
        self.0 ^= rhs.0;
    }
}

impl BitAnd for Int128 {
    type Output = Self;
    #[inline]
    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitOr for Int128 {
    type Output = Self;
    #[inline]
    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl Not for Int128 {
    type Output = Self;
    #[inline]
    fn not(self) -> Self::Output {
        Self(!self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug() {
        assert_eq!(format!("{:?}", Int128::new(42)), "Int128(42)");
        assert_eq!(format!("{:?}", Int128::new(-10)), "Int128(-10)");
        assert_eq!(format!("{:?}", Int128::ZERO), "Int128(0)");
    }

    #[test]
    fn test_constants() {
        assert_eq!(Int128::ZERO, Int128::new(0));
        assert_eq!(Int128::ONE, Int128::new(1));
        assert_eq!(Int128::MINUS_ONE, Int128::new(-1));
    }

    #[test]
    fn test_lo_hi_positive() {
        // Construct a value with distinct hi and lo parts
        let val = Int128::new((1i128 << 64) | 0x123456789ABCDEF0i128);
        assert_eq!(val.hi(), 1i64);
        assert_eq!(val.lo(), 0x123456789ABCDEF0i64);
    }

    #[test]
    fn test_lo_hi_negative() {
        // -1i128 is all 1s in binary, so both halves should be -1i64
        let val = Int128::new(-1i128);
        assert_eq!(val.lo(), -1i64);
        assert_eq!(val.hi(), -1i64);
    }

    #[test]
    fn test_lo_hi_bounds() {
        // i128::MAX: upper 64 bits are i64::MAX, lower 64 bits are all 1s (-1i64)
        let max = Int128::new(i128::MAX);
        assert_eq!(max.hi(), i64::MAX);
        assert_eq!(max.lo(), -1i64);

        // i128::MIN: upper 64 bits are i64::MIN (1 followed by 63 zeros), lower 64 bits are 0
        let min = Int128::new(i128::MIN);
        assert_eq!(min.hi(), i64::MIN);
        assert_eq!(min.lo(), 0i64);
    }

    #[test]
    fn test_add() {
        assert_eq!(Int128::new(5) + Int128::new(3), Int128::new(8));
        assert_eq!(Int128::new(-5) + Int128::new(3), Int128::new(-2));

        // Wrapping add: i128::MAX + 1 wraps to i128::MIN
        let max = Int128::new(i128::MAX);
        assert_eq!(max + Int128::new(1), Int128::new(i128::MIN));
    }

    #[test]
    fn test_sub() {
        assert_eq!(Int128::new(5) - Int128::new(3), Int128::new(2));
        assert_eq!(Int128::new(-5) - Int128::new(3), Int128::new(-8));

        // Wrapping sub: i128::MIN - 1 wraps to i128::MAX
        let min = Int128::new(i128::MIN);
        assert_eq!(min - Int128::new(1), Int128::new(i128::MAX));
    }

    #[test]
    fn test_mul() {
        assert_eq!(Int128::new(5) * Int128::new(3), Int128::new(15));
        assert_eq!(Int128::new(-5) * Int128::new(3), Int128::new(-15));

        // Wrapping mul: i128::MAX * 2 wraps to -2
        let max = Int128::new(i128::MAX);
        assert_eq!(max * Int128::new(2), Int128::new(-2));
    }

    #[test]
    fn test_neg() {
        assert_eq!(-Int128::new(5), Int128::new(-5));
        assert_eq!(-Int128::new(0), Int128::new(0));
        assert_eq!(-Int128::new(-42), Int128::new(42));

        // Wrapping neg: negating i128::MIN wraps back to i128::MIN
        let min = Int128::new(i128::MIN);
        assert_eq!(-min, Int128::new(i128::MIN));
    }

    #[test]
    fn test_byte_serialization() {
        // A value with distinct, recognizable bytes in both halves
        let val = Int128::new(0x0123456789ABCDEF_FEDCBA9876543210i128);

        // Test Big-Endian
        let be_bytes = val.to_be_bytes();
        assert_eq!(be_bytes[0], 0x01, "BE first byte should be 0x01");
        assert_eq!(be_bytes[15], 0x10, "BE last byte should be 0x10");
        assert_eq!(Int128::from_be_bytes(be_bytes), val, "BE round-trip failed");

        // Test Little-Endian
        let le_bytes = val.to_le_bytes();
        assert_eq!(le_bytes[0], 0x10, "LE first byte should be 0x10");
        assert_eq!(le_bytes[15], 0x01, "LE last byte should be 0x01");
        assert_eq!(Int128::from_le_bytes(le_bytes), val, "LE round-trip failed");
    }

    #[test]
    fn test_rotate_left() {
        let val = Int128::new(1);

        // Basic rotation
        assert_eq!(val.rotate_left(1), Int128::new(2));
        assert_eq!(val.rotate_left(2), Int128::new(4));

        // Full rotation wraps around to the original value
        assert_eq!(val.rotate_left(128), Int128::new(1));
        assert_eq!(val.rotate_left(129), Int128::new(2));

        // Rotating the sign bit (bit 127) to the least significant bit
        let high_bit = Int128::new(1i128 << 127);
        assert_eq!(high_bit.rotate_left(1), Int128::new(1));
    }

    #[test]
    fn test_rotate_right() {
        let val = Int128::new(2);

        // Basic rotation
        assert_eq!(val.rotate_right(1), Int128::new(1));

        // Full rotation wraps around to the original value
        assert_eq!(val.rotate_right(128), Int128::new(2));
        assert_eq!(val.rotate_right(129), Int128::new(1));

        // Rotating the least significant bit to the sign bit (bit 127)
        let low_bit = Int128::new(1);
        assert_eq!(low_bit.rotate_right(1), Int128::new(1i128 << 127));
    }

    #[test]
    fn test_rotate_negative() {
        // -1 is all 1s in two's complement, so rotation should not change it
        let all_ones = Int128::new(-1);
        assert_eq!(all_ones.rotate_left(42), Int128::new(-1));
        assert_eq!(all_ones.rotate_right(42), Int128::new(-1));

        // Test rotation on a specific negative pattern
        let val = Int128::new(1i128 << 127); // Only the sign bit is set
        assert_eq!(val.rotate_right(1), Int128::new(1i128 << 126));
    }

    #[test]
    fn test_bitxor() {
        let a = Int128::new(0b1010);
        let b = Int128::new(0b1100);
        assert_eq!(a ^ b, Int128::new(0b0110));

        // Test with negative numbers (all 1s in two's complement)
        let all_ones = Int128::new(-1);
        let zero = Int128::new(0);
        assert_eq!(all_ones ^ zero, Int128::new(-1));
        assert_eq!(all_ones ^ all_ones, Int128::new(0));
    }
}