//! Thin arithmetic wrapper around Flock's unchanged native GHASH F128.
//! Integer constructors encode polynomial-basis labels, NOT the prime-subfield
//! embedding. Every address/type/interpolation formula must respect that fact.
use flock_core::field::F128;
use serde::{Deserialize, Serialize};
use std::ops::*;
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(transparent)]
pub struct F(pub F128);
impl F {
    pub const ZERO: Self = Self(F128::ZERO);
    pub const ONE: Self = Self(F128::ONE);
    pub const TWO: Self = Self(F128::new(2, 0)); // label X, never 1+1
    #[inline]
    pub const fn from_u64(v: u64) -> Self {
        Self(F128::new(v, 0))
    }
    #[inline]
    pub const fn from_usize(v: usize) -> Self {
        Self::from_u64(v as u64)
    }
    #[inline]
    pub const fn from_bool(v: bool) -> Self {
        Self::from_u64(v as u64)
    }
    #[inline]
    pub const fn from_u128(v: u128) -> Self {
        Self(F128::new(v as u64, (v >> 64) as u64))
    }
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.0.is_zero()
    }
    #[inline]
    pub fn inverse(self) -> Self {
        assert!(!self.is_zero());
        Self(self.0.inv())
    }
    #[inline]
    pub fn square(self) -> Self {
        self * self
    }
    #[inline]
    pub fn exp_u64(self, mut n: u64) -> Self {
        let mut x = self;
        let mut r = Self::ONE;
        while n != 0 {
            if n & 1 != 0 {
                r *= x;
            }
            x = x * x;
            n >>= 1;
        }
        r
    }
    #[inline]
    pub fn exp_const_u64<const N: u64>(self) -> Self {
        self.exp_u64(N)
    }
    pub fn bytes(self) -> [u8; 16] {
        ((self.0.lo as u128) | ((self.0.hi as u128) << 64)).to_le_bytes()
    }
}
impl Add for F {
    type Output = Self;
    #[inline]
    fn add(self, r: Self) -> Self {
        Self(self.0 + r.0)
    }
}
impl Sub for F {
    type Output = Self;
    #[inline]
    fn sub(self, r: Self) -> Self {
        Self(self.0 + r.0)
    }
}
impl Mul for F {
    type Output = Self;
    #[inline]
    fn mul(self, r: Self) -> Self {
        Self(self.0 * r.0)
    }
}
impl Neg for F {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        self
    }
}
impl AddAssign for F {
    #[inline]
    fn add_assign(&mut self, r: Self) {
        self.0 += r.0;
    }
}
impl SubAssign for F {
    #[inline]
    fn sub_assign(&mut self, r: Self) {
        self.0 += r.0;
    }
}
impl MulAssign for F {
    #[inline]
    fn mul_assign(&mut self, r: Self) {
        self.0 *= r.0;
    }
}
impl std::iter::Sum for F {
    fn sum<I: Iterator<Item = Self>>(i: I) -> Self {
        i.fold(Self::ZERO, |a, b| a + b)
    }
}
impl std::iter::Product for F {
    fn product<I: Iterator<Item = Self>>(i: I) -> Self {
        i.fold(Self::ONE, |a, b| a * b)
    }
}
pub(crate) fn batch_multiplicative_inverse_general(a: &[F], out: &mut [F], inv: impl Fn(F) -> F) {
    assert_eq!(a.len(), out.len());
    let mut product = F::ONE;
    for (&x, y) in a.iter().zip(out.iter_mut()) {
        *y = product;
        product *= x;
    }
    let mut suffix = inv(product);
    for (&x, y) in a.iter().zip(out.iter_mut()).rev() {
        let prefix = *y;
        *y = prefix * suffix;
        suffix *= x;
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Point<T>(pub Vec<T>);
impl<T> Point<T> {
    pub fn new(v: Vec<T>) -> Self {
        Self(v)
    }
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn primitive_level_generator() {
        fn pow(mut x: F, mut n: u128) -> F {
            let mut a = F::ONE;
            while n != 0 {
                if n & 1 != 0 {
                    a *= x;
                }
                x = x * x;
                n >>= 1;
            }
            a
        }
        let primes = [
            3u128,
            5,
            17,
            257,
            641,
            65537,
            274177,
            6700417,
            67280421310721,
        ];
        assert_eq!(primes.iter().product::<u128>(), u128::MAX);
        for p in primes {
            assert_ne!(pow(F::TWO, u128::MAX / p), F::ONE);
        }
        assert_eq!(pow(F::TWO, u128::MAX), F::ONE);
        assert_eq!(F::ONE + F::ONE, F::ZERO);
    }
}
