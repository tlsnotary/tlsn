//! Circuits for arithmetic with large numbers.

use std::cell::RefCell;

use utils::bits::ToBitsIter;

use crate::{
    ops::binary::{switch_nbit, wrapping_add_nbit, wrapping_sub_nbit},
    types::U8,
    BuilderState, Node, Tracer,
};

/// Add two numbers modulo a constant modulus.
///
/// This circuit assumes that the summands are in the range [0, modulus).
///
/// # Arguments
///
/// * `state` - The builder state to append the circuit to.
/// * `a` - The first number encoded as an array of bytes in big-endian order.
/// * `b` - The second number encoded as an array of bytes in big-endian order.
/// * `modulus` - The modulus encoded as an array of bytes in big-endian order.
///
/// # Returns
///
/// (a + b) % modulus
pub fn nbyte_add_mod_trace<'a, const N: usize>(
    state: &'a RefCell<BuilderState>,
    mut a: [Tracer<'a, U8>; N],
    mut b: [Tracer<'a, U8>; N],
    mut modulus: [u8; N],
) -> [Tracer<'a, U8>; N] {
    // Reverse the arrays to be little-endian
    a.reverse();
    b.reverse();
    modulus.reverse();

    // NO OPERATIONS USING CONST GENERICS YET :(
    // Otherwise, we would just use a const generic array here with length (N * 8) + 1
    let mut a_bits = a
        .into_iter()
        .flat_map(|a| a.to_inner().nodes().into_iter())
        .collect::<Vec<_>>();
    let mut b_bits = b
        .into_iter()
        .flat_map(|b| b.to_inner().nodes().into_iter())
        .collect::<Vec<_>>();
    let mut modulus_bits = modulus
        .into_iter()
        .flat_map(|m| m.into_lsb0_iter())
        .map(|bit| Node::new(bit as usize))
        .collect::<Vec<_>>();

    // Tack on an extra bit to absorb overflow
    a_bits.push(Node::new(0));
    b_bits.push(Node::new(0));
    modulus_bits.push(Node::new(0));

    let sum = wrapping_add_nbit(&mut state.borrow_mut(), &a_bits, &b_bits);

    let (rem, underflow) = wrapping_sub_nbit(&mut state.borrow_mut(), &sum, &modulus_bits);

    // if sum < modulus { sum } else { sum - modulus }
    let mut sum_reduced = switch_nbit(&mut state.borrow_mut(), &rem, &sum, underflow);

    // Pop off the extra bit
    sum_reduced.pop();

    let mut sum_reduced: [U8; N] = sum_reduced
        .chunks(8)
        .map(|chunk| U8::new(chunk.try_into().unwrap()))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    // Reverse the array back to big-endian
    sum_reduced.reverse();

    sum_reduced.map(|v| Tracer::new(state, v))
}

#[cfg(test)]
mod tests {
    use mpc_circuits_macros::evaluate;

    use crate::CircuitBuilder;

    use super::*;

    #[test]
    fn test_nbyte_add_mod() {
        let builder = CircuitBuilder::new();

        let a = builder.add_array_input::<u8, 2>();
        let b = builder.add_array_input::<u8, 2>();
        let modulus = [0u8, 239u8];

        let sum = nbyte_add_mod_trace(builder.state(), a, b, modulus).map(|v| v.to_inner());

        builder.add_output(sum);

        let circ = builder.build().unwrap();

        for a in 0u8..modulus[1] {
            for b in 0u8..modulus[1] {
                let expected_sum = ((a as u16 + b as u16) % modulus[1] as u16) as u8;

                let sum: [u8; 2] = evaluate!(circ, fn([0u8, a], [0u8, b]) -> [u8; 2]).unwrap();
                let sum = u16::from_be_bytes(sum) as u8;

                assert_eq!(sum, expected_sum);
            }
        }
    }
}
