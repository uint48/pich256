use std::fmt;
use std::ops::{Add, Mul, Neg, Sub};

/// A 192-bit signed integer type, represented as three 64-bit limbs.
/// Layout is `[lo, mid, hi]` on little-endian, `[hi, mid, lo]` on big-endian.
/// `#[repr(transparent)]` guarantees it has the exact same 24-byte memory layout as `[i64; 3]`.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
#[repr(transparent)]
pub struct I192(pub [i64; 3]);

impl fmt::Debug for I192 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "I192(hi: {}, mid: {}, lo: {})", self.hi(), self.mid(), self.lo())
    }
}

impl I192 {
    pub const ZERO: Self = I192([0; 3]);
    pub const ONE: Self = I192::new(0, 0, 1);
    pub const MINUS_ONE: Self = I192::new(-1, -1, -1);

    #[inline]
    pub const fn new(hi: i64, mid: i64, lo: i64) -> Self {
        #[cfg(target_endian = "little")]
        {
            Self([lo, mid, hi])
        }
        #[cfg(target_endian = "big")]
        {
            Self([hi, mid, lo])
        }
    }

    #[inline]
    pub const fn lo(&self) -> i64 {
        #[cfg(target_endian = "little")]
        {
            self.0[0]
        }
        #[cfg(target_endian = "big")]
        {
            self.0[2]
        }
    }

    #[inline]
    pub const fn mid(&self) -> i64 {
        self.0[1]
    }

    #[inline]
    pub const fn hi(&self) -> i64 {
        #[cfg(target_endian = "little")]
        {
            self.0[2]
        }
        #[cfg(target_endian = "big")]
        {
            self.0[0]
        }
    }

    /// Converts the integer to a 24-byte array in big-endian order.
    pub fn to_be_bytes(self) -> [u8; 24] {
        let mut bytes = [0u8; 24];
        bytes[0..8].copy_from_slice(&self.hi().to_be_bytes());
        bytes[8..16].copy_from_slice(&self.mid().to_be_bytes());
        bytes[16..24].copy_from_slice(&self.lo().to_be_bytes());
        bytes
    }

    /// Creates a new integer from a 24-byte array in big-endian order.
    pub fn from_be_bytes(bytes: [u8; 24]) -> Self {
        let hi = i64::from_be_bytes(bytes[0..8].try_into().unwrap());
        let mid = i64::from_be_bytes(bytes[8..16].try_into().unwrap());
        let lo = i64::from_be_bytes(bytes[16..24].try_into().unwrap());
        Self::new(hi, mid, lo)
    }
}

impl Add for I192 {
    type Output = Self;
    #[inline]
    fn add(self, rhs: Self) -> Self::Output {
        let (lo, c1) = (self.lo() as u64).overflowing_add(rhs.lo() as u64);
        let (mid, c2) = (self.mid() as u64).overflowing_add(rhs.mid() as u64);
        let (mid, c1_mid) = mid.overflowing_add(c1 as u64);
        let carry = (c2 as u64) + (c1_mid as u64);
        let hi = self.hi().wrapping_add(rhs.hi()).wrapping_add(carry as i64);
        Self::new(hi, mid as i64, lo as i64)
    }
}

impl Sub for I192 {
    type Output = Self;
    #[inline]
    fn sub(self, rhs: Self) -> Self::Output {
        let (lo, b1) = (self.lo() as u64).overflowing_sub(rhs.lo() as u64);
        let (mid, b2) = (self.mid() as u64).overflowing_sub(rhs.mid() as u64);
        let (mid, b1_mid) = mid.overflowing_sub(b1 as u64);
        let borrow = (b2 as u64) + (b1_mid as u64);
        let hi = self.hi().wrapping_sub(rhs.hi()).wrapping_sub(borrow as i64);
        Self::new(hi, mid as i64, lo as i64)
    }
}

impl Neg for I192 {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self::Output {
        // Two's complement: invert all bits and add 1, propagating the carry.
        // Carry must come from `overflowing_add`, not from checking whether a
        // limb's result is zero: a limb can legitimately compute to zero with
        // no carry-out (e.g. `!(-1i64) as u64 == 0` when there's no carry-in).
        let (lo, c1) = (!self.lo() as u64).overflowing_add(1);
        let (mid, c2) = (!self.mid() as u64).overflowing_add(c1 as u64);
        let hi = (!self.hi() as u64).wrapping_add(c2 as u64);
        Self::new(hi as i64, mid as i64, lo as i64)
    }
}

impl Mul for I192 {
    type Output = Self;
    #[inline]
    fn mul(self, rhs: Self) -> Self::Output {
        let a1 = self.hi() as u64;
        let b1 = self.mid() as u64;
        let c1 = self.lo() as u64;

        let a2 = rhs.hi() as u64;
        let b2 = rhs.mid() as u64;
        let c2 = rhs.lo() as u64;

        #[inline]
        fn mul_u64(x: u64, y: u64) -> (u64, u64) {
            let p = (x as u128) * (y as u128);
            ((p >> 64) as u64, p as u64)
        }

        // 1. lo limb
        let (p0_hi, p0_lo) = mul_u64(c1, c2);
        let lo = p0_lo;

        // 2. mid limb
        // We accumulate in u128 to guarantee no overflow during intermediate sums
        let mut mid_sum = p0_hi as u128;
        let mut carry_mid = 0u128;

        let (p1_hi, p1_lo) = mul_u64(c1, b2);
        mid_sum += p1_lo as u128;
        carry_mid += p1_hi as u128;

        let (p2_hi, p2_lo) = mul_u64(b1, c2);
        mid_sum += p2_lo as u128;
        carry_mid += p2_hi as u128;

        let mid = mid_sum as u64;
        carry_mid += mid_sum >> 64;

        // 3. hi limb
        let mut hi_sum = carry_mid;

        // Contributions to the hi limb. The `hi` part of these products is >= 2^192, so we drop it.
        // We use `_` to explicitly tell the compiler we are intentionally discarding the high part.
        let (_, p3_lo) = mul_u64(c1, a2);
        hi_sum += p3_lo as u128;

        let (_, p4_lo) = mul_u64(b1, b2);
        hi_sum += p4_lo as u128;

        let (_, p5_lo) = mul_u64(a1, c2);
        hi_sum += p5_lo as u128;

        let hi = hi_sum as u64; // Truncates to lower 64 bits, correctly dropping >= 2^192

        Self::new(hi as i64, mid as i64, lo as i64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_debug_format() {
        let val = I192::new(100, 50, 42);
        assert_eq!(format!("{:?}", val), "I192(hi: 100, mid: 50, lo: 42)");
    }

    #[test]
    fn test_constants() {
        assert_eq!(I192::ZERO, I192::new(0, 0, 0));
        assert_eq!(I192::ONE, I192::new(0, 0, 1));
        assert_eq!(I192::MINUS_ONE, I192::new(-1, -1, -1));
    }

    #[test]
    fn test_add_with_carry() {
        let a = I192::new(10, 5, -1); // -1 in lo is u64::MAX
        let b = I192::new(5, 2, 1);
        let c = a + b;
        assert_eq!(c.lo(), 0);
        assert_eq!(c.mid(), 8);  // 5 + 2 + 1 (carry)
        assert_eq!(c.hi(), 15);  // 10 + 5
    }

    #[test]
    fn test_add_wrapping() {
        // Max positive 192-bit value + 1 should wrap to minimum negative value
        let a = I192::new(i64::MAX, -1, -1);
        let b = I192::ONE;
        let c = a + b;

        // Mathematically: (2^191 - 1) + 1 = 2^191
        // In 192-bit two's complement, 2^191 is the minimum negative value:
        // hi = i64::MIN (0x8000_0000_0000_0000), mid = 0, lo = 0
        assert_eq!(c.hi(), i64::MIN);
        assert_eq!(c.mid(), 0);
        assert_eq!(c.lo(), 0);
    }

    #[test]
    fn test_sub_with_borrow() {
        let a = I192::new(20, 10, 0);
        let b = I192::new(10, 5, 1);
        let c = a - b;
        assert_eq!(c.lo(), -1); // u64::MAX represented as i64
        assert_eq!(c.mid(), 4); // 10 - 5 - 1 (borrow)
        assert_eq!(c.hi(), 10); // 20 - 10
    }

    #[test]
    fn test_neg() {
        let zero = I192::ZERO;
        assert_eq!((-zero), I192::ZERO);

        let one = I192::ONE;
        assert_eq!((-one), I192::MINUS_ONE);

        let val = I192::new(100, 50, 42);
        let sum = val + (-val);
        assert_eq!(sum, I192::ZERO);
    }

    #[test]
    fn test_neg_min() {
        // Negating the minimum value should wrap to itself (standard two's complement behavior)
        let min = I192::new(i64::MIN, 0, 0);
        let neg_min = -min;
        assert_eq!(neg_min, min);
    }

    #[test]
    fn test_mul_simple() {
        let a = I192::new(0, 0, 2);
        let b = I192::new(0, 0, 3);
        assert_eq!(a * b, I192::new(0, 0, 6));
    }

    #[test]
    fn test_mul_with_carry() {
        // (1 << 64) * (1 << 64) = 1 << 128
        // 1 << 64 is represented as hi=0, mid=1, lo=0
        let a = I192::new(0, 1, 0);
        let b = I192::new(0, 1, 0);
        let c = a * b;

        // Result should be 1 << 128, which is hi=1, mid=0, lo=0
        assert_eq!(c.hi(), 1);
        assert_eq!(c.mid(), 0);
        assert_eq!(c.lo(), 0);
    }

    #[test]
    fn test_mul_negative() {
        let minus_one = I192::MINUS_ONE;
        assert_eq!(minus_one * minus_one, I192::ONE);

        let two = I192::new(0, 0, 2);
        let three = I192::new(0, 0, 3);

        // -6 in 192-bit two's complement requires sign extension:
        // hi=-1, mid=-1, lo=-6
        let minus_six = I192::new(-1, -1, -6);

        assert_eq!((-two) * three, minus_six);
        assert_eq!(three * (-two), minus_six);
    }

    #[test]
    fn test_mul_large() {
        // (2^129 - 1) * (2^129 - 1) mod 2^192
        // 2^129 - 1 is represented as hi=1, mid=-1, lo=-1
        let a = I192::new(1, -1, -1);
        let c = a * a;

        // Expected: (2^129 - 1)^2 = 2^258 - 2^130 + 1.
        // Modulo 2^192, this is -2^130 + 1.
        // In 192-bit two's complement:
        // lo = 1
        // mid = 0 (the carry from adding 1 propagates entirely through the mid limb)
        // hi = -4 (bits 128-191 are all 1s except bit 130, which is 0)
        assert_eq!(c.hi(), -4);
        assert_eq!(c.mid(), 0);
        assert_eq!(c.lo(), 1);
    }

    #[test]
    fn test_mul_commutative() {
        let a = I192::new(123, 456, 789);
        let b = I192::new(987, 654, 321);
        assert_eq!(a * b, b * a);
    }
}