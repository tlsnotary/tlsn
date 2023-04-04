use std::ops::BitXor;

use crate::{
    components::{Feed, Node},
    types::Bit,
    BuilderState, Tracer,
};

/// Binary full-adder.
fn full_adder(
    state: &mut BuilderState,
    a: Node<Feed>,
    b: Node<Feed>,
    c_in: Node<Feed>,
) -> (Node<Feed>, Node<Feed>) {
    // SUM = A ⊕ B ⊕ C_IN
    let a_b = state.add_xor_gate(a, b);
    let sum = state.add_xor_gate(a_b, c_in);

    // C_OUT = C_IN ⊕ ((A ⊕ C_IN) ^ (B ⊕ C_IN))
    let a_c_in = state.add_xor_gate(a, c_in);
    let b_c_in = state.add_xor_gate(b, c_in);
    let and = state.add_and_gate(a_c_in, b_c_in);
    let c_out = state.add_xor_gate(and, c_in);

    (sum, c_out)
}

/// Binary half-adder.
fn half_adder(state: &mut BuilderState, a: Node<Feed>, b: Node<Feed>) -> (Node<Feed>, Node<Feed>) {
    // SUM = A ⊕ B
    let sum = state.add_xor_gate(a, b);
    // C_OUT = A ^ B
    let c_out = state.add_and_gate(a, b);

    (sum, c_out)
}

/// Add two nbit values together, wrapping on overflow.
pub(crate) fn const_wrapping_add_nbit<const N: usize>(
    state: &mut BuilderState,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    let mut c_out = Node::new(0);
    std::array::from_fn(|n| {
        if n == 0 {
            // no carry in
            let (sum_0, c_out_0) = half_adder(state, a[0], b[0]);
            c_out = c_out_0;
            sum_0
        } else if n < N {
            let (sum_n, c_out_n) = full_adder(state, a[n], b[n], c_out);
            c_out = c_out_n;
            sum_n
        } else {
            // no carry out
            state.add_xor_gate(a[N - 1], b[N - 1])
        }
    })
}

/// Add two nbit values together, wrapping on overflow.
pub(crate) fn wrapping_add_nbit(
    state: &mut BuilderState,
    a: &[Node<Feed>],
    b: &[Node<Feed>],
) -> Vec<Node<Feed>> {
    assert_eq!(a.len(), b.len());

    let len = a.len();
    let mut c_out = Node::new(0);
    a.iter()
        .zip(b)
        .enumerate()
        .map(|(n, (a, b))| {
            if n == 0 {
                // no carry in
                let (sum_0, c_out_0) = half_adder(state, *a, *b);
                c_out = c_out_0;
                sum_0
            } else if n < len {
                let (sum_n, c_out_n) = full_adder(state, *a, *b, c_out);
                c_out = c_out_n;
                sum_n
            } else {
                // no carry out
                state.add_xor_gate(*a, *b)
            }
        })
        .collect()
}

/// Subtract two nbit values, wrapping on underflow.
///
/// Returns the result and the bit indicating whether underflow occurred.
pub(crate) fn const_wrapping_sub_nbit<const N: usize>(
    state: &mut BuilderState,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> ([Node<Feed>; N], Node<Feed>) {
    // invert b
    let b_inv = b.map(|b| state.add_inv_gate(b));

    // Set first b_in to 1, which adds 1 to b_inv.
    let mut b_out = Node::new(1);
    let diff = std::array::from_fn(|n| {
        let (diff_n, b_out_n) = full_adder(state, a[n], b_inv[n], b_out);
        b_out = b_out_n;
        diff_n
    });

    // underflow occured if b_out is 0
    let underflow = state.add_inv_gate(b_out);

    (diff, underflow)
}

/// Subtract two nbit values, wrapping on underflow.
///
/// Returns the result and the bit indicating whether underflow occurred.
pub(crate) fn wrapping_sub_nbit(
    state: &mut BuilderState,
    a: &[Node<Feed>],
    b: &[Node<Feed>],
) -> (Vec<Node<Feed>>, Node<Feed>) {
    assert_eq!(a.len(), b.len());

    // invert b
    let b_inv = b.iter().map(|b| state.add_inv_gate(*b)).collect::<Vec<_>>();

    // Set first b_in to 1, which adds 1 to b_inv.
    let mut b_out = Node::new(1);

    let diff = a
        .iter()
        .zip(b_inv)
        .map(|(a, b_inv)| {
            let (diff_n, b_out_n) = full_adder(state, *a, b_inv, b_out);
            b_out = b_out_n;
            diff_n
        })
        .collect();

    // underflow occured if b_out is 0
    let underflow = state.add_inv_gate(b_out);

    (diff, underflow)
}

/// Switch between two nbit values.
///
/// If `toggle` is 0, the result is `a`, otherwise it is `b`.
pub(crate) fn switch_nbit(
    state: &mut BuilderState,
    a: &[Node<Feed>],
    b: &[Node<Feed>],
    toggle: Node<Feed>,
) -> Vec<Node<Feed>> {
    assert_eq!(a.len(), b.len());

    let not_toggle = state.add_inv_gate(toggle);

    a.iter()
        .zip(b)
        .map(|(a, b)| {
            let a_and_not_toggle = state.add_and_gate(*a, not_toggle);
            let b_and_toggle = state.add_and_gate(*b, toggle);
            state.add_xor_gate(a_and_not_toggle, b_and_toggle)
        })
        .collect()
}

/// Bitwise XOR of two nbit values.
pub(crate) fn xor_nbit<const N: usize>(
    state: &mut BuilderState,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    std::array::from_fn(|n| state.add_xor_gate(a[n], b[n]))
}

/// Bitwise AND of two nbit values.
pub(crate) fn and_nbit<const N: usize>(
    state: &mut BuilderState,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    std::array::from_fn(|n| state.add_and_gate(a[n], b[n]))
}

/// Bitwise OR of two nbit values.
pub(crate) fn or_nbit<const N: usize>(
    state: &mut BuilderState,
    a: [Node<Feed>; N],
    b: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    std::array::from_fn(|n| {
        // OR = (A ⊕ B) ⊕ (A ^ B)
        let a_xor_b = state.add_xor_gate(a[n], b[n]);
        let a_and_b = state.add_and_gate(a[n], b[n]);

        state.add_xor_gate(a_xor_b, a_and_b)
    })
}

/// Bitwise NOT of an nbit value.
pub(crate) fn inv_nbit<const N: usize>(
    state: &mut BuilderState,
    a: [Node<Feed>; N],
) -> [Node<Feed>; N] {
    std::array::from_fn(|n| state.add_inv_gate(a[n]))
}

impl<'a> BitXor<Tracer<'a, Bit>> for Tracer<'a, Bit> {
    type Output = Tracer<'a, Bit>;

    fn bitxor(self, rhs: Tracer<'a, Bit>) -> Self::Output {
        let mut state = self.state.borrow_mut();

        let out = state.add_xor_gate(self.to_inner().nodes()[0], rhs.to_inner().nodes()[0]);

        let value = Bit::new([out]);

        drop(state);

        Tracer::new(self.state, value)
    }
}

#[cfg(test)]
mod tests {
    use mpc_circuits_macros::evaluate;

    use super::*;

    use crate::{types::U8, CircuitBuilder};

    #[test]
    fn test_wrapping_add() {
        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>().to_inner();
        let b = builder.add_input::<u8>().to_inner();

        let sum = U8::new(const_wrapping_add_nbit(
            &mut builder.state().borrow_mut(),
            a.nodes(),
            b.nodes(),
        ));

        builder.add_output(sum);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected_sum = a.wrapping_add(b);

                let sum: u8 = evaluate!(circ, fn(a, b) -> u8).unwrap();

                assert_eq!(sum, expected_sum);
            }
        }
    }

    #[test]
    fn test_wrapping_sub() {
        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>().to_inner();
        let b = builder.add_input::<u8>().to_inner();

        let (rem, borrow) =
            const_wrapping_sub_nbit(&mut builder.state().borrow_mut(), a.nodes(), b.nodes());

        let rem = U8::new(rem);
        let borrow = Bit::new([borrow]);

        builder.add_output(rem);
        builder.add_output(borrow);

        let circ = builder.build().unwrap();

        for a in 0u8..=255 {
            for b in 0u8..=255 {
                let expected_rem = a.wrapping_sub(b);
                let expected_underflow = a < b;

                let (rem, underflow): (u8, bool) = evaluate!(circ, fn(a, b) -> (u8, bool)).unwrap();

                assert_eq!(rem, expected_rem);
                assert_eq!(underflow, expected_underflow);
            }
        }
    }

    #[test]
    fn test_switch_nbit() {
        let builder = CircuitBuilder::new();

        let a = builder.add_input::<u8>().to_inner();
        let b = builder.add_input::<u8>().to_inner();
        let toggle = builder.add_input::<bool>().to_inner();

        let out = U8::new(
            switch_nbit(
                &mut builder.state().borrow_mut(),
                a.nodes().as_slice(),
                b.nodes().as_slice(),
                toggle.nodes()[0],
            )
            .try_into()
            .unwrap(),
        );

        builder.add_output(out);

        let circ = builder.build().unwrap();

        let a = 42u8;
        let b = 69u8;

        let out: u8 = evaluate!(circ, fn(a, b, false) -> u8).unwrap();
        assert_eq!(out, a);

        let out: u8 = evaluate!(circ, fn(a, b, true) -> u8).unwrap();
        assert_eq!(out, b);
    }
}
