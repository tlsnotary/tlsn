//! This module helps defining the role for the instance used in the key exchange protocol

/// A trait which depending on the Role allows to get the correct input numbers for the circuit
pub trait Role {
    /// Get the correct input number for the first input
    fn first_input(&self) -> usize;
    /// Get the correct input number for the second input
    fn second_input(&self) -> usize;
    /// Get the correct input number for the third input
    fn third_input(&self) -> usize;
    /// Get the correct input number for the fourth input
    fn fourth_input(&self) -> usize;
}

/// A struct which implements the `Role` trait for the leader
#[derive(Copy, Clone, Debug)]
pub struct Leader;

impl Role for Leader {
    fn first_input(&self) -> usize {
        0
    }

    fn second_input(&self) -> usize {
        2
    }

    fn third_input(&self) -> usize {
        1
    }

    fn fourth_input(&self) -> usize {
        3
    }
}

/// A struct which implements the `Role` trait for the follower
#[derive(Copy, Clone, Debug)]
pub struct Follower;

impl Role for Follower {
    fn first_input(&self) -> usize {
        1
    }

    fn second_input(&self) -> usize {
        3
    }

    fn third_input(&self) -> usize {
        0
    }

    fn fourth_input(&self) -> usize {
        2
    }
}
