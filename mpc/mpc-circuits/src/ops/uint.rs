use std::ops::{BitAnd, BitOr, BitXor, Not, Shl, Shr};

use crate::{
    types::{U128, U16, U32, U64, U8},
    Tracer,
};

use super::{binary, WrappingAdd, WrappingSub};

macro_rules! impl_wrapping_add_uint {
    ($ty:ident, $const_ty:ident, $len:expr) => {
        impl<'a> WrappingAdd<Tracer<'a, $ty>> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn wrapping_add(self, rhs: Tracer<'a, $ty>) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let nodes = binary::const_wrapping_add_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.to_inner().nodes(),
                );

                let value = <$ty>::new(nodes);

                drop(state);

                Tracer::new(self.state, value)
            }
        }

        impl<'a> WrappingAdd<$const_ty> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn wrapping_add(self, rhs: $const_ty) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let rhs = state.get_constant::<$const_ty>(rhs);

                let value = $ty::new(binary::const_wrapping_add_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.nodes(),
                ));

                drop(state);

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_wrapping_add_uint!(U8, u8, 8);
impl_wrapping_add_uint!(U16, u16, 16);
impl_wrapping_add_uint!(U32, u32, 32);
impl_wrapping_add_uint!(U64, u64, 64);
impl_wrapping_add_uint!(U128, u128, 128);

macro_rules! impl_wrapping_sub_uint {
    ($ty:ident, $const_ty:ident, $len:expr) => {
        impl<'a> WrappingSub<Tracer<'a, $ty>> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn wrapping_sub(self, rhs: Tracer<'a, $ty>) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let (nodes, _) = binary::const_wrapping_sub_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.to_inner().nodes(),
                );

                let value = <$ty>::new(nodes);

                drop(state);

                Tracer::new(self.state, value)
            }
        }

        impl<'a> WrappingSub<$const_ty> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn wrapping_sub(self, rhs: $const_ty) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let rhs = state.get_constant::<$const_ty>(rhs);

                let (nodes, _) = binary::const_wrapping_sub_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.nodes(),
                );

                let value = <$ty>::new(nodes);

                drop(state);

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_wrapping_sub_uint!(U8, u8, 8);
impl_wrapping_sub_uint!(U16, u16, 16);
impl_wrapping_sub_uint!(U32, u32, 32);
impl_wrapping_sub_uint!(U64, u64, 64);
impl_wrapping_sub_uint!(U128, u128, 128);

macro_rules! impl_bitxor_uint {
    ($ty:ident, $const_ty:ident, $len:expr) => {
        impl<'a> BitXor<Tracer<'a, $ty>> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn bitxor(self, rhs: Tracer<'a, $ty>) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let value = <$ty>::new(binary::xor_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.to_inner().nodes(),
                ));

                drop(state);

                Tracer::new(self.state, value)
            }
        }

        impl<'a> BitXor<$const_ty> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn bitxor(self, rhs: $const_ty) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let rhs = state.get_constant::<$const_ty>(rhs);

                let value = <$ty>::new(binary::xor_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.nodes(),
                ));

                drop(state);

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_bitxor_uint!(U8, u8, 8);
impl_bitxor_uint!(U16, u16, 16);
impl_bitxor_uint!(U32, u32, 32);
impl_bitxor_uint!(U64, u64, 64);
impl_bitxor_uint!(U128, u128, 128);

macro_rules! impl_bit_and_uint {
    ($ty:ident, $const_ty:ident, $len:expr) => {
        impl<'a> BitAnd<Tracer<'a, $ty>> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn bitand(self, rhs: Tracer<'a, $ty>) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let value = <$ty>::new(binary::and_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.to_inner().nodes(),
                ));

                drop(state);

                Tracer::new(self.state, value)
            }
        }

        impl<'a> BitAnd<$const_ty> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn bitand(self, rhs: $const_ty) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let rhs = state.get_constant::<$const_ty>(rhs);

                let value = <$ty>::new(binary::and_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.nodes(),
                ));

                drop(state);

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_bit_and_uint!(U8, u8, 8);
impl_bit_and_uint!(U16, u16, 16);
impl_bit_and_uint!(U32, u32, 32);
impl_bit_and_uint!(U64, u64, 64);
impl_bit_and_uint!(U128, u128, 128);

macro_rules! impl_bit_or_uint {
    ($ty:ident, $const_ty:ident, $len:expr) => {
        impl<'a> BitOr<Tracer<'a, $ty>> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn bitor(self, rhs: Tracer<'a, $ty>) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let value = <$ty>::new(binary::or_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.to_inner().nodes(),
                ));

                drop(state);

                Tracer::new(self.state, value)
            }
        }

        impl<'a> BitOr<$const_ty> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn bitor(self, rhs: $const_ty) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let rhs = state.get_constant::<$const_ty>(rhs);

                let value = <$ty>::new(binary::or_nbit::<$len>(
                    &mut state,
                    self.to_inner().nodes(),
                    rhs.nodes(),
                ));

                drop(state);

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_bit_or_uint!(U8, u8, 8);
impl_bit_or_uint!(U16, u16, 16);
impl_bit_or_uint!(U32, u32, 32);
impl_bit_or_uint!(U64, u64, 64);
impl_bit_or_uint!(U128, u128, 128);

macro_rules! impl_shl_uint {
    ($ty:ident, $len:expr) => {
        impl<'a> Shl<usize> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn shl(self, rhs: usize) -> Self::Output {
                assert!(rhs <= $len);

                let state = self.state.borrow();

                let const_zero = state.get_const_zero();

                let mut nodes = self.to_inner().nodes();
                // Bits are LSB0, so we rotate right
                nodes.rotate_right(rhs);
                // Replace the lsbs with 0s
                nodes[..rhs].iter_mut().for_each(|node| *node = const_zero);

                let value = <$ty>::new(nodes);

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_shl_uint!(U8, 8);
impl_shl_uint!(U16, 16);
impl_shl_uint!(U32, 32);
impl_shl_uint!(U64, 64);
impl_shl_uint!(U128, 128);

macro_rules! impl_shr_uint {
    ($ty:ident, $len:expr) => {
        impl<'a> Shr<usize> for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn shr(self, rhs: usize) -> Self::Output {
                assert!(rhs <= $len);

                let state = self.state.borrow();

                let const_zero = state.get_const_zero();

                let mut nodes = self.to_inner().nodes();
                // Bits are LSB0, so we rotate left
                nodes.rotate_left(rhs);
                // Replace the msbs with 0s
                nodes[$len - rhs - 1..]
                    .iter_mut()
                    .for_each(|node| *node = const_zero);

                let value = <$ty>::new(nodes);

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_shr_uint!(U8, 8);
impl_shr_uint!(U16, 16);
impl_shr_uint!(U32, 32);
impl_shr_uint!(U64, 64);
impl_shr_uint!(U128, 128);

macro_rules! impl_neg_uint {
    ($ty:ident) => {
        impl<'a> Not for Tracer<'a, $ty> {
            type Output = Tracer<'a, $ty>;

            fn not(self) -> Self::Output {
                let mut state = self.state.borrow_mut();

                let value = <$ty>::new(binary::inv_nbit(&mut state, self.to_inner().nodes()));

                Tracer::new(self.state, value)
            }
        }
    };
}

impl_neg_uint!(U8);
impl_neg_uint!(U16);
impl_neg_uint!(U32);
impl_neg_uint!(U64);
impl_neg_uint!(U128);
