use std::{ops::BitXor, sync::Arc};

use crate::{MpcTlsError, TlsRole};
use mpz_circuits::{types::ValueType, Circuit, CircuitBuilder, Tracer};
use mpz_memory_core::{
    binary::Binary, ClearValue, DecodeFutureTyped, Memory, MemoryExt, MemoryType, Repr, StaticSize,
    Vector, View, ViewExt,
};
use mpz_vm_core::{CallBuilder, Vm, VmExt};
use rand::{distributions::Standard, prelude::Distribution, thread_rng, Rng};

pub(crate) struct Decode<R> {
    role: TlsRole,
    value: R,
    otp_0: R,
    otp_1: R,
    len: usize,
}

impl<R> Decode<R>
where
    R: Repr<Binary> + StaticSize<Binary>,
{
    pub(crate) fn new<V>(vm: &mut V, role: TlsRole, value: R) -> Result<Self, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let otp_0: R = vm.alloc().map_err(MpcTlsError::vm)?;
        let otp_1: R = vm.alloc().map_err(MpcTlsError::vm)?;
        let decode = Self {
            role,
            value,
            otp_0,
            otp_1,
            len: R::SIZE,
        };

        Ok(decode)
    }
}

impl<R> Decode<Vector<R>>
where
    R: Repr<Binary> + StaticSize<Binary>,
{
    pub(crate) fn new_vec<V>(
        vm: &mut V,
        role: TlsRole,
        value: Vector<R>,
    ) -> Result<Self, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
    {
        let len = value.len() * R::SIZE;
        let otp_0: Vector<R> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
        let otp_1: Vector<R> = vm.alloc_vec(len).map_err(MpcTlsError::vm)?;
        let decode = Self {
            role,
            value,
            otp_0,
            otp_1,
            len,
        };

        Ok(decode)
    }
}

impl<R> Decode<R>
where
    R: Repr<Binary, Clear: Clone> + Copy,
{
    pub(crate) fn private<V>(self, vm: &mut V) -> Result<OneTimePadPrivate<R>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
        Standard: Distribution<R::Clear>,
    {
        let otp_value = match self.role {
            TlsRole::Leader => {
                let mut rng = thread_rng();
                let otp_value = rng.gen();

                vm.mark_private(self.otp_0).map_err(MpcTlsError::vm)?;
                vm.assign(self.otp_0, otp_value.clone())
                    .map_err(MpcTlsError::vm)?;
                Some(otp_value)
            }
            TlsRole::Follower => {
                vm.mark_blind(self.otp_0).map_err(MpcTlsError::vm)?;
                None
            }
        };
        vm.commit(self.otp_0).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(self.otp_0)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output: R = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadPrivate {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }

    pub(crate) fn shared<V>(self, vm: &mut V) -> Result<OneTimePadShared<R>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
        Standard: Distribution<R::Clear>,
    {
        let mut rng = thread_rng();
        let otp_value = rng.gen();

        let mut otp_0 = self.otp_0;
        let mut otp_1 = self.otp_1;
        if let TlsRole::Follower = self.role {
            std::mem::swap(&mut otp_0, &mut otp_1);
        }
        vm.mark_private(otp_0).map_err(MpcTlsError::vm)?;
        vm.mark_blind(otp_1).map_err(MpcTlsError::vm)?;
        vm.assign(otp_0, otp_value.clone())
            .map_err(MpcTlsError::vm)?;

        vm.commit(otp_0).map_err(MpcTlsError::vm)?;
        vm.commit(otp_1).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp_shared(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(otp_0)
            .arg(otp_1)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output: R = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadShared {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }
}

pub(crate) struct OneTimePadPrivate<R: Repr<Binary>> {
    role: TlsRole,
    value: DecodeFutureTyped<<Binary as MemoryType>::Raw, R::Clear>,
    otp: Option<R::Clear>,
}

impl<R> OneTimePadPrivate<R>
where
    R: Repr<Binary, Clear: BitXor<Output = R::Clear>> + Memory<Binary> + StaticSize<Binary>,
{
    pub(crate) async fn decode(self) -> Result<Option<R::Clear>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => {
                let otp = self.otp.expect("Otp should be set for leader");
                let out = Some(otp ^ value);
                Ok(out)
            }
            TlsRole::Follower => Ok(None),
        }
    }
}

impl<R> OneTimePadPrivate<Vector<R>>
where
    R: Repr<Binary, Clear: BitXor<Output = R::Clear>> + Memory<Binary> + StaticSize<Binary>,
    Vec<R::Clear>: ClearValue<Binary>,
{
    pub(crate) async fn decode_vec(self) -> Result<Option<Vec<R::Clear>>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => {
                let otp = self.otp.expect("Otp should be set for leader");
                let out: Vec<R::Clear> = value
                    .into_iter()
                    .zip(otp.into_iter())
                    .map(|(v, o)| v ^ o)
                    .collect();
                Ok(Some(out))
            }
            TlsRole::Follower => Ok(None),
        }
    }
}

pub(crate) struct OneTimePadShared<R: Repr<Binary>> {
    role: TlsRole,
    value: DecodeFutureTyped<<Binary as MemoryType>::Raw, R::Clear>,
    otp: R::Clear,
}

impl<R> OneTimePadShared<R>
where
    R: Repr<Binary, Clear: BitXor<Output = R::Clear>> + Memory<Binary> + StaticSize<Binary>,
{
    pub(crate) async fn decode(self) -> Result<R::Clear, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => Ok(self.otp ^ value),
            TlsRole::Follower => Ok(self.otp),
        }
    }
}

impl<R> OneTimePadShared<Vector<R>>
where
    R: Repr<Binary, Clear: BitXor<Output = R::Clear>> + Memory<Binary> + StaticSize<Binary>,
    Vec<R::Clear>: ClearValue<Binary>,
{
    pub(crate) async fn decode_vec(self) -> Result<Vec<R::Clear>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode)?;
        match self.role {
            TlsRole::Leader => {
                let value: Vec<R::Clear> = value
                    .into_iter()
                    .zip(self.otp.into_iter())
                    .map(|(v, o)| v ^ o)
                    .collect();
                Ok(value)
            }
            TlsRole::Follower => Ok(self.otp),
        }
    }
}

/// Builds a circuit for applying one-time pads to the provided values.
pub(crate) fn build_otp(len: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    let input = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp = builder.add_input_by_type(ValueType::new_array::<u8>(len));

    let input = Tracer::new(builder.state(), input);
    let otp = Tracer::new(builder.state(), otp);
    let masked = input ^ otp;
    builder.add_output(masked);

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}

/// Builds a circuit for applying one-time pads to secret share the provided values.
pub(crate) fn build_otp_shared(len: usize) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    let input = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp_0 = builder.add_input_by_type(ValueType::new_array::<u8>(len));
    let otp_1 = builder.add_input_by_type(ValueType::new_array::<u8>(len));

    let input = Tracer::new(builder.state(), input);
    let otp_0 = Tracer::new(builder.state(), otp_0);
    let otp_1 = Tracer::new(builder.state(), otp_1);
    let masked = input ^ otp_0 ^ otp_1;
    builder.add_output(masked);

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}
