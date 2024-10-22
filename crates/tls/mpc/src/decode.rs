use cipher::{Cipher, CipherCircuit, Keystream};
use mpz_circuits::types::ValueType;
use mpz_memory_core::{
    binary::{Binary, U8},
    Memory, MemoryExt, Repr, StaticSize, Vector, View, ViewExt,
};
use mpz_vm_core::{Vm, VmExt};
use rand::{distributions::Standard, prelude::Distribution, thread_rng};
use tls_core::msgs::message::PlainMessage;

use crate::{error::Kind, MpcTlsError, TlsRole};

pub struct Decode<R> {
    role: TlsRole,
    value: R,
}

impl<R> Decode<R>
where
    R: Repr<Binary> + StaticSize,
{
    pub fn new(role: TlsRole, value: R) -> Self {
        Self { role, value }
    }

    pub fn open<V>(&mut self, vm: &mut V, len: usize) -> Result<(), MpcTlsError>
    where
        V: Vm<Binary> + View<Binary>,
        Standard: Distribution<R::Clear>,
    {
        let (otp, otp_value): (R, Option<R::Clear>) = match self.role {
            TlsRole::Leader => {
                let mut rng = thread_rng();
                let otp_value = rng.gen();

                let otp = vm.alloc().map_err(|err| {
                    MpcTlsError::new_with_source(Kind::Vm, "unable to allocate for otp", err)
                })?;
                vm.mark_private(otp).map_err(|err| {
                    MpcTlsError::new_with_source(Kind::Vm, "unable to set visibility for otp", err)
                })?;
                vm.assign(otp, otp_value).map_err(|err| {
                    MpcTlsError::new_with_source(Kind::Vm, "unable to assign value for  otp", err)
                })?;
                vm.commit(otp).map_err(|err| {
                    MpcTlsError::new_with_source(Kind::Vm, "unable to commit value for otp", err)
                })?;

                (otp, Some(otp_value))
            }
            TlsRole::Follower => {
                let otp = vm.alloc().map_err(|err| {
                    MpcTlsError::new_with_source(Kind::Vm, "unable to allocate for otp", err)
                })?;
                vm.mark_private(otp).map_err(|err| {
                    MpcTlsError::new_with_source(Kind::Vm, "unable to set visibility for otp", err)
                })?;
                vm.commit(otp).map_err(|err| {
                    MpcTlsError::new_with_source(Kind::Vm, "unable to commit value for otp", err)
                })?;

                (otp, None)
            }
        };

        let circuit = build_otp_circuit(&[ValueType::new_array(R::SIZE)]);
        let call = CallBuilder::new(<Aes128 as CipherCircuit>::otp())
            .arg(value)
            .arg(otp)
            .build()
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        let value = vm
            .call(call)
            .map_err(|err| AesError::new(ErrorKind::Vm, err))?;

        Ok((value, otp_value))
    }
}

/// Builds a circuit for applying one-time pads to the provided values.
pub(crate) fn build_otp_circuit(inputs: &[ValueType]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    for input_ty in inputs {
        let input = builder.add_input_by_type(input_ty.clone());
        let otp = builder.add_input_by_type(input_ty.clone());

        let input = Tracer::new(builder.state(), input);
        let otp = Tracer::new(builder.state(), otp);
        let masked = input ^ otp;
        builder.add_output(masked);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}

/// Builds a circuit for applying one-time pads to secret share the provided values.
pub(crate) fn build_otp_shared_circuit(inputs: &[ValueType]) -> Arc<Circuit> {
    let builder = CircuitBuilder::new();

    for input_ty in inputs {
        let input = builder.add_input_by_type(input_ty.clone());
        let otp_0 = builder.add_input_by_type(input_ty.clone());
        let otp_1 = builder.add_input_by_type(input_ty.clone());

        let input = Tracer::new(builder.state(), input);
        let otp_0 = Tracer::new(builder.state(), otp_0);
        let otp_1 = Tracer::new(builder.state(), otp_1);
        let masked = input ^ otp_0 ^ otp_1;
        builder.add_output(masked);
    }

    let circ = builder.build().expect("circuit should be valid");

    Arc::new(circ)
}
