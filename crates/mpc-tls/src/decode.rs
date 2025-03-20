use std::{
    array::from_fn,
    future::Future,
    pin::Pin,
    task::{ready, Context, Poll},
};

use crate::Role;
use mpz_core::bitvec::BitVec;
use mpz_memory_core::{
    binary::{Binary, U8},
    DecodeError, DecodeFutureTyped,
};
use mpz_vm_core::{prelude::*, Vm, VmError};
use pin_project_lite::pin_project;
use rand::Rng;

pin_project! {
    /// Supports decoding into additive shares.
    #[project = OneTimePadSharedProj]
    pub(crate) enum OneTimePadShared<T> {
        Leader {
            otp: T,
        },
        Follower {
            #[pin] value: DecodeFutureTyped<BitVec, T>,
            otp: T,
        }
    }
}

impl<const N: usize> OneTimePadShared<[u8; N]> {
    pub(crate) fn new(
        role: Role,
        value: Array<U8, N>,
        vm: &mut dyn Vm<Binary>,
    ) -> Result<Self, VmError> {
        let mut rng = rand::rng();
        let otp: [u8; N] = from_fn(|_| rng.random());
        match role {
            Role::Leader => {
                let masked = vm.mask_private(value, otp)?;
                let masked = vm.mask_blind(masked)?;
                _ = vm.decode(masked)?;

                Ok(Self::Leader { otp })
            }
            Role::Follower => {
                let masked = vm.mask_blind(value)?;
                let masked = vm.mask_private(masked, otp)?;
                let value = vm.decode(masked)?;

                Ok(Self::Follower { value, otp })
            }
        }
    }
}

impl Future for OneTimePadShared<[u8; 16]> {
    type Output = Result<[u8; 16], DecodeError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            OneTimePadSharedProj::Leader { otp } => Poll::Ready(Ok(*otp)),
            OneTimePadSharedProj::Follower { value, otp } => {
                let mut value = ready!(value.poll(cx))?;
                value.iter_mut().zip(otp).for_each(|(a, b)| *a ^= *b);
                Poll::Ready(Ok(value))
            }
        }
    }
}
