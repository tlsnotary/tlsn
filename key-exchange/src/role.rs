//! This module helps defining the role for the instance used in the key exchange protocol

/// A trait which depending on the Role allows to get the correct input numbers for the circuit
pub trait Role: sealed::Sealed {
    /// Get the correct input number for the first input
    fn input_0(&self) -> usize;
    /// Get the correct input number for the second input
    fn input_1(&self) -> usize;
    /// Get the correct input number for the third input
    fn input_2(&self) -> usize;
    /// Get the correct input number for the fourth input
    fn input_3(&self) -> usize;
}

/// A struct which implements the `Role` trait for the leader
#[derive(Copy, Clone, Debug)]
pub struct Leader;

impl Role for Leader {
    /// This corresponds to PMS share A
    fn input_0(&self) -> usize {
        0
    }

    /// This corresponds to PMS share C
    fn input_1(&self) -> usize {
        2
    }

    /// This corresponds to PMS share B
    fn input_2(&self) -> usize {
        1
    }

    /// This corresponds to PMS share D
    fn input_3(&self) -> usize {
        3
    }
}

/// A struct which implements the `Role` trait for the follower
#[derive(Copy, Clone, Debug)]
pub struct Follower;

impl Role for Follower {
    /// This corresponds to PMS share B
    fn input_0(&self) -> usize {
        1
    }

    /// This corresponds to PMS share D
    fn input_1(&self) -> usize {
        3
    }

    /// This corresponds to PMS share A
    fn input_2(&self) -> usize {
        0
    }

    /// This corresponds to PMS share C
    fn input_3(&self) -> usize {
        2
    }
}

mod sealed {
    use super::*;

    pub trait Sealed {}

    impl Sealed for Leader {}
    impl Sealed for Follower {}
}
