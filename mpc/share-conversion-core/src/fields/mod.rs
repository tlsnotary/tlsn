pub mod gf2_128;
pub mod p256;

use std::{
    fmt::Debug,
    ops::{Add, Mul},
};

pub trait Field:
    Add<Output = Self> + Mul<Output = Self> + Copy + Clone + Debug + 'static + Send + Sync
{
    const BIT_SIZE: usize;
    fn inverse(self) -> Self;
}

/// Iteratively multiplies some field element with another field element
///
/// This function multiplies the last element in `powers` with some other field element `factor`
/// and appends the result to `powers`. This process is repeated `count` times.
///
/// * `powers` - The vector to which the new higher powers get pushed
/// * `factor` - The field element with which the last element of the vector is multiplied
/// * `count` - How many products are computed
pub fn compute_product_repeated<T: Field>(powers: &mut Vec<T>, factor: T, count: usize) {
    for _ in 0..count {
        let last_power = *powers
            .last()
            .expect("Vector is empty. Cannot compute higher powers");
        powers.push(factor * last_power);
    }
}
