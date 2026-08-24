use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

// repr(transparent): This is a memory layout attribute. It tells the Rust compiler:
// "Guarantee that this struct has the exact same memory layout, size, and alignment as its single inner field ([i128; 2])."
// It ensures there is no hidden "padding" bytes added by the compiler.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct I256(pub [i128; 2]);

impl fmt::Debug for I256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I256(hi: {}, lo: {})", self.hi(), self.lo())
    }
}

impl I256 {
    /// The additive identity for this integer type, i.e. `0`.
    pub const ZERO: Self = I256([0; 2]);

    /// The multiplicative identity for this integer type, i.e. `1`.
    pub const ONE: Self = I256::new(0, 1);

    /// The multiplicative inverse for this integer type, i.e. `-1`.
    pub const MINUS_ONE: Self = I256::new(-1, -1);

    #[inline]
    pub const fn new(hi: i128, lo: i128) -> Self {
        #[cfg(target_endian = "little")]
        {
            // Assuming little-endian style: index 0 is the lower 128 bits, index 1 is the upper
            Self([lo, hi])
        }
        #[cfg(target_endian = "big")]
        {
            Self([hi, lo])
        }
    }

    #[inline]
    pub const fn lo(&self) -> i128 {
        #[cfg(target_endian = "little")]
        {
            self.0[0]
        }
        #[cfg(target_endian = "big")]
        {
            self.0[1]
        }
    }

    #[inline]
    pub const fn hi(&self) -> i128 {
        #[cfg(target_endian = "little")]
        {
            self.0[1]
        }
        #[cfg(target_endian = "big")]
        {
            self.0[0]
        }
    }
}

impl Add for I256 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let (lo, carry) = (self.lo() as u128).overflowing_add(rhs.lo() as u128);
        let hi = self.hi().wrapping_add(rhs.hi()).wrapping_add(carry as i128);
        Self::new(hi, lo as i128) // Use Self::new for endianness safety
    }
}

impl Sub for I256 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let (lo, borrow) = (self.lo() as u128).overflowing_sub(rhs.lo() as u128);
        let hi = self.hi().wrapping_sub(rhs.hi()).wrapping_sub(borrow as i128);
        Self::new(hi, lo as i128) // Use Self::new for endianness safety
    }
}

impl Neg for I256 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output {
        // Two's complement: invert all bits and add 1
        let lo = (!self.lo() as u128).wrapping_add(1);
        let hi = (!self.hi()).wrapping_add((lo == 0) as i128);
        Self::new(hi, lo as i128) // Use Self::new for endianness safety
    }
}

impl Mul for I256 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let a = self.hi() as u128;
        let b = self.lo() as u128;
        let c = rhs.hi() as u128;
        let d = rhs.lo() as u128;

        // We only need the lower 256 bits of the 512-bit product.
        // (a*2^128 + b) * (c*2^128 + d) = a*c*2^256 + (a*d + b*c)*2^128 + b*d
        // We drop a*c*2^256.
        let (hi_bd, lo_bd) = mul_u128(b, d);
        let (_, lo_ad) = mul_u128(a, d);
        let (_, lo_bc) = mul_u128(b, c);

        // Sum the contributions to the upper 128 bits.
        // Any overflow from this sum represents a value >= 2^256, which is correctly dropped.
        let mid1 = hi_bd.wrapping_add(lo_ad);
        let hi_result = mid1.wrapping_add(lo_bc);
        let lo_result = lo_bd;

        Self::new(hi_result as i128, lo_result as i128)
    }
}

/// Helper: Multiplies two 128-bit integers, returning a 256-bit result as (hi, lo).
#[inline]
fn mul_u128(a: u128, b: u128) -> (u128, u128) {
    let a_lo = a as u64;
    let a_hi = (a >> 64) as u64;
    let b_lo = b as u64;
    let b_hi = (b >> 64) as u64;

    let p0 = (a_lo as u128) * (b_lo as u128);
    let p1 = (a_lo as u128) * (b_hi as u128);
    let p2 = (a_hi as u128) * (b_lo as u128);
    let p3 = (a_hi as u128) * (b_hi as u128);

    let mid = (p0 >> 64) + (p1 & 0xFFFFFFFFFFFFFFFF) + (p2 & 0xFFFFFFFFFFFFFFFF);
    let lo = (p0 & 0xFFFFFFFFFFFFFFFF) | ((mid & 0xFFFFFFFFFFFFFFFF) << 64);
    let hi = p3 + (mid >> 64) + (p1 >> 64) + (p2 >> 64);
    (hi, lo)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_format() {
        let val = I256::new(100, 42);
        let debug_str = format!("{:?}", val);
        assert_eq!(debug_str, "I256(hi: 100, lo: 42)");
    }


    #[test]
    fn test_constants() {
        assert_eq!(I256::ZERO.lo(), 0);
        assert_eq!(I256::ZERO.hi(), 0);

        assert_eq!(I256::ONE.lo(), 1);
        assert_eq!(I256::ONE.hi(), 0);

        assert_eq!(I256::MINUS_ONE.lo(), -1);
        assert_eq!(I256::MINUS_ONE.hi(), -1);
    }

    #[test]
    fn test_new_and_accessors() {
        // new(hi, lo)
        let val = I256::new(100, 42);
        assert_eq!(val.lo(), 42);
        assert_eq!(val.hi(), 100);
    }

    #[test]
    fn test_default_and_eq() {
        let a = I256::default();
        let b = I256::ZERO;
        assert_eq!(a, b);

        let c = I256::new(2, 1);
        let d = I256::new(2, 1);
        assert_eq!(c, d);
        assert_ne!(c, b);
    }

    #[test]
    fn test_add_no_carry() {
        let a = I256::new(20, 10);
        let b = I256::new(15, 5);
        let c = a + b;
        assert_eq!(c.lo(), 15);
        assert_eq!(c.hi(), 35);
    }

    #[test]
    fn test_add_with_carry() {
        // -1 as i128 is all 1s in binary (u128::MAX).
        // Adding 1 should overflow lo to 0 and carry 1 to hi.
        //
        //          High 128 bits          Low 128 bits
        //         -----------------        -----------------
        //   a =    0x0000_0000_000A   +   0xFFFF_FFFF_FFFF_FFFF  (-1 as i128)
        //   b =    0x0000_0000_0005   +   0x0000_0000_0000_0001   (1 as i128)
        //         -----------------        -----------------
        //   lo:  (0xFFFF_FFFF_FFFF_FFFF + 0x0000_0000_0000_0001)
        //        = 0x0000_0000_0000_0000  (with a carry of 1)
        //
        //   hi:  (0x0000_0000_000A + 0x0000_0000_0005) + 1 (carry)
        //        = 0x0000_0000_0010  (which is 16 in decimal)
        //
        // Result: c = I256::new(16, 0)

        let a = I256::new(10, -1);
        let b = I256::new(5, 1);
        let c = a + b;
        assert_eq!(c.lo(), 0);
        assert_eq!(c.hi(), 16); // 10 + 5 + 1 (carry)
    }

    #[test]
    fn test_add_wrapping() {
        // Test wrapping behavior on hi when it exceeds i128::MAX
        //
        //          High 128 bits                     Low 128 bits
        //         -----------------------------     -----------------------------
        //   a =    0x7FFF_FFFF_FFFF_FFFF_FFFF_   +   0xFFFF_FFFF_FFFF_FFFF_FFFF_  (i128::MAX, -1)
        //          FFFF_FFFF_FFFF_FFFF               FFFF_FFFF_FFFF_FFFF
        //   b =    0x0000_0000_0000_0000_0000_   +   0x0000_0000_0000_0000_0000_  (0, 1)
        //          0000_0000_0000_0000               0000_0000_0000_0001
        //         -----------------------------     -----------------------------
        //   lo:  (0xFFFF...FFFF + 0x0000...0001)
        //        = 0x0000_0000_0000_0000_0000_0000_0000_0000  (overflows to 0, carry = 1)
        //
        //   hi:  (0x7FFF...FFFF + 0x0000...0000) + 1 (carry)
        //        = 0x8000_0000_0000_0000_0000_0000_0000_0000  (wraps to i128::MIN)
        //
        // Result: c = I256::new(i128::MIN, 0)

        let a = I256::new(i128::MAX, -1);
        let b = I256::new(0, 1);
        let c = a + b;
        assert_eq!(c.lo(), 0);
        assert_eq!(c.hi(), i128::MIN); // i128::MAX + 1 wraps to i128::MIN
    }

    #[test]
    fn test_sub_no_borrow() {
        let a = I256::new(30, 20);
        let b = I256::new(15, 10);
        let c = a - b;
        assert_eq!(c.lo(), 10);
        assert_eq!(c.hi(), 15);
    }

    #[test]
    fn test_sub_with_borrow() {
        // 0 - 1 should borrow from hi
        let a = I256::new(20, 0);
        let b = I256::new(10, 1);
        let c = a - b;
        assert_eq!(c.lo(), -1); // u128::MAX represented as i128
        assert_eq!(c.hi(), 9);  // 20 - 10 - 1 (borrow)
    }

    #[test]
    fn test_sub_wrapping() {
        let a = I256::new(i128::MIN, 0);
        let b = I256::new(0, 1);
        let c = a - b;
        assert_eq!(c.lo(), -1);
        assert_eq!(c.hi(), i128::MAX); // i128::MIN - 1 wraps to i128::MAX
    }

    #[test]
    fn test_neg() {
        let zero = I256::ZERO;
        assert_eq!((-zero).lo(), 0);
        assert_eq!((-zero).hi(), 0);

        let one = I256::ONE;
        let neg_one = -one;
        assert_eq!(neg_one, I256::MINUS_ONE);

        let val = I256::new(100, 42);
        let neg_val = -val;

        // A number plus its negation should equal ZERO
        let sum = val + neg_val;
        assert_eq!(sum.lo(), 0);
        assert_eq!(sum.hi(), 0);
    }

    #[test]
    fn test_neg_min() {
        // Negating the minimum value should wrap to itself (standard two's complement behavior)
        let min = I256::new(i128::MIN, 0);
        let neg_min = -min;
        assert_eq!(neg_min.lo(), 0);
        assert_eq!(neg_min.hi(), i128::MIN);
    }

    #[test]
    fn test_mul_zero() {
        let a = I256::new(100, 42);
        let zero = I256::ZERO;
        assert_eq!(a * zero, zero);
        assert_eq!(zero * a, zero);
    }

    #[test]
    fn test_mul_one() {
        let a = I256::new(100, 42);
        let one = I256::ONE;
        assert_eq!(a * one, a);
        assert_eq!(one * a, a);
    }

    #[test]
    fn test_mul_simple() {
        let a = I256::new(0, 2);
        let b = I256::new(0, 3);
        let c = a * b;
        assert_eq!(c.hi(), 0);
        assert_eq!(c.lo(), 6);
    }

    #[test]
    fn test_mul_with_carry() {
        // (1 << 64) * (1 << 64) = 1 << 128
        // In I256, 1 << 64 is hi=0, lo=(1 << 64)
        let shift = 1u128 << 64;
        let a = I256::new(0, shift as i128);
        let b = I256::new(0, shift as i128);
        let c = a * b;

        // Result should be 1 << 128, which is hi=1, lo=0
        assert_eq!(c.hi(), 1);
        assert_eq!(c.lo(), 0);
    }

    #[test]
    fn test_mul_negative() {
        // -1 * -1 = 1
        let minus_one = I256::MINUS_ONE;
        let one = I256::ONE;
        assert_eq!(minus_one * minus_one, one);

        // -2 * 3 = -6
        let two = I256::new(0, 2);
        let minus_two = -two;
        let three = I256::new(0, 3);
        let six = I256::new(0, 6);
        let minus_six = -six;

        assert_eq!(minus_two * three, minus_six);
        assert_eq!(three * minus_two, minus_six);
    }

    #[test]
    fn test_mul_large() {
        // (2^129 - 1) * (2^129 - 1) mod 2^256
        // 2^129 - 1 is represented as hi=1, lo=u128::MAX (which is -1 as i128)
        let a = I256::new(1, -1);
        let c = a * a;

        // Expected: (2^129 - 1)^2 = 2^258 - 2^130 + 1.
        // Modulo 2^256, this is -2^130 + 1.
        // In 256-bit two's complement, -2^130 + 1 has:
        // hi = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC (which is -4 as i128)
        // lo = 0x00000000000000000000000000000001 (which is 1)
        assert_eq!(c.hi(), -4);
        assert_eq!(c.lo(), 1);
    }

    #[test]
    fn test_mul_commutative() {
        let a = I256::new(123, 456);
        let b = I256::new(789, 101112);
        assert_eq!(a * b, b * a);
    }

    #[test]
    fn test_mul_min() {
        // Minimum value squared should be 0 mod 2^256
        // because I256::MIN is a multiple of 2^128, and (k*2^128)^2 = k^2 * 2^256 = 0 mod 2^256
        let min = I256::new(i128::MIN, 0);
        let res = min * min;
        assert_eq!(res, I256::ZERO);
    }
}