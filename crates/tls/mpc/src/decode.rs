use std::{ops::BitXor, sync::Arc};

use crate::{MpcTlsError, TlsRole};
use cipher::Cipher;
use mpz_circuits::{types::ValueType, Circuit, CircuitBuilder, Tracer};
use mpz_memory_core::{
    binary::Binary, DecodeFutureTyped, Memory, MemoryExt, MemoryType, Repr, StaticSize, Vector,
    View, ViewExt,
};
use mpz_vm_core::{CallBuilder, Vm, VmExt};
use rand::{distributions::Standard, prelude::Distribution, thread_rng};

pub struct Decode<R> {
    role: TlsRole,
    value: R,
    len: usize,
}

impl<R> Decode<R>
where
    R: Repr<Binary> + StaticSize<Binary>,
{
    pub fn new(role: TlsRole, value: R) -> Self {
        Self {
            role,
            value,
            len: R::SIZE,
        }
    }
}

impl<R> Decode<Vector<R>>
where
    R: Repr<Binary> + StaticSize<Binary>,
{
    pub fn new_vec(role: TlsRole, value: Vector<R>) -> Self {
        let rng = thread_rng();
        let otp = rng.gen();

        Self {
            role,
            value,
            len: R::SIZE * value.len(),
        }
    }
}

impl<R> Decode<R>
where
    R: Repr<Binary>,
{
    pub fn private<V>(self, vm: &mut V) -> Result<OneTimePadPrivate<R>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
        Standard: Distribution<R::Clear>,
    {
        let otp = vm.alloc().map_err(MpcTlsError::vm)?;

        let (otp, otp_value) = match self.role {
            TlsRole::Leader => {
                let rng = thread_rng();
                let otp_value = rng.gen();

                vm.mark_private(otp).map_err(MpcTlsError::vm)?;
                vm.assign(otp, otp_value).map_err(MpcTlsError::vm)?;
                (otp, otp_value)
            }
            TlsRole::Follower => {
                vm.mark_blind(otp).map_err(MpcTlsError::vm)?;
                (otp, None)
            }
        };
        vm.commit(otp).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(otp)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadPrivate {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }

    pub fn shared<V>(self, vm: &mut V) -> Result<OneTimePadShared<R>, MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
        Standard: Distribution<R::Clear>,
    {
        let rng = thread_rng();
        let otp_0 = vm.alloc().map_err(MpcTlsError::vm)?;
        let otp_1 = vm.alloc().map_err(MpcTlsError::vm)?;
        let otp_value = rng.gen();

        if let TlsRole::Follower = self.role {
            std::mem::swap(&mut otp_0, &mut otp_1);
        }
        vm.mark_private(otp_0).map_err(MpcTlsError::vm)?;
        vm.mark_blind(otp_1).map_err(MpcTlsError::vm)?;
        vm.assign(otp_0, otp_value).map_err(MpcTlsError::vm)?;

        vm.commit(otp_0).map_err(MpcTlsError::vm)?;
        vm.commit(otp_1).map_err(MpcTlsError::vm)?;

        let otp_circuit = build_otp_shared(self.len);
        let call = CallBuilder::new(otp_circuit)
            .arg(self.value)
            .arg(otp_0)
            .arg(otp_1)
            .build()
            .map_err(MpcTlsError::vm)?;

        let output = vm.call(call).map_err(MpcTlsError::vm)?;
        let output = vm.decode(output).map_err(MpcTlsError::vm)?;

        let otp = OneTimePadPrivate {
            role: self.role,
            value: output,
            otp: otp_value,
        };

        Ok(otp)
    }
}

pub struct OneTimePadPrivate<R: Repr<Binary>> {
    role: TlsRole,
    value: DecodeFutureTyped<<Binary as MemoryType>::Raw, R::Clear>,
    otp: Option<R::Clear>,
}

impl<R> OneTimePadPrivate<R>
where
    R: Repr<Binary> + Memory<Binary> + BitXor,
{
    pub async fn decode(self) -> Result<Option<R::Clear>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode);
        match self.role {
            TlsRole::Leader => {
                let otp = self.otp.expect("Otp should be set for leader");
                let out = Some(otp ^ self.value);
                Ok(out)
            }
            TlsRole::Follower => Ok(None),
        }
    }
}

impl<R> OneTimePadPrivate<R>
where
    R: Repr<Binary> + Memory<Binary> + IntoIterator<Item: BitXor>,
{
    pub async fn decode(self) -> Result<Option<R::Clear>, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode);
        match self.role {
            TlsRole::Leader => {
                let otp = self.otp.expect("Otp should be set for leader");
                let out: Vec<R::Clear> = self
                    .value
                    .into_iter()
                    .zip(otp.into_iter())
                    .map(|v, o| v ^ o)
                    .collect();
                Ok(out)
            }
            TlsRole::Follower => Ok(None),
        }
    }
}

pub struct OneTimePadShared<R: Repr<Binary>> {
    role: TlsRole,
    value: DecodeFutureTyped<<Binary as MemoryType>::Raw, R::Clear>,
    otp: R::Clear,
}

impl<R> OneTimePadShared<R>
where
    R: Repr<Binary> + Memory<Binary> + BitXor,
{
    pub async fn decode(self) -> Result<R::Clear, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode);
        match self.role {
            TlsRole::Leader => todo!(),
            TlsRole::Follower => todo!(),
        }
    }
}

impl<R> OneTimePadPrivate<R>
where
    R: Repr<Binary> + Memory<Binary> + IntoIterator<Item: BitXor>,
{
    pub async fn decode(self) -> Result<R::Clear, MpcTlsError> {
        let value = self.value.await.map_err(MpcTlsError::decode);
        match self.role {
            TlsRole::Leader => todo!(),
            TlsRole::Follower => todo!(),
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
