use crate::{sha256::Sha256, Config, PrfError, PrfOutput, SessionKeys};
use mpz_circuits::{circuits::xor, Circuit, CircuitBuilder};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U32, U8},
        Array, FromRaw, MemoryExt, StaticSize, ToRaw, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};
use std::{fmt::Debug, sync::Arc};
use tracing::instrument;

mod state;
use state::State;

pub(crate) mod function;
use function::Prf;

/// MPC PRF for computing TLS 1.2 HMAC-SHA256 PRF.
#[derive(Debug)]
pub struct MpcPrf {
    config: Config,
    state: State,
    circuits: Option<Circuits>,
}

impl MpcPrf {
    /// Creates a new instance of the PRF.
    ///
    /// # Arguments
    ///
    /// `config` - The PRF config.
    pub fn new(config: Config) -> MpcPrf {
        Self {
            config,
            state: State::Initialized,
            circuits: None,
        }
    }

    /// Allocates resources for the PRF.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    /// * `pms` - The pre-master secret.
    #[instrument(level = "debug", skip_all, err)]
    pub fn alloc(
        &mut self,
        vm: &mut dyn Vm<Binary>,
        pms: Array<U8, 32>,
    ) -> Result<PrfOutput, PrfError> {
        let State::Initialized = self.state.take() else {
            return Err(PrfError::state("PRF not in initialized state"));
        };

        let circuits = Circuits::alloc(self.config, vm, pms.into())?;

        let keys = circuits.get_session_keys(vm)?;
        let cf_vd = circuits.get_client_finished_vd(vm)?;
        let sf_vd = circuits.get_server_finished_vd(vm)?;

        let prf_output = PrfOutput { keys, cf_vd, sf_vd };

        self.circuits = Some(circuits);
        self.state = State::SessionKeys {
            client_random: None,
        };

        Ok(prf_output)
    }

    /// Sets the client random.
    ///
    /// # Arguments
    ///
    /// * `random` - The client random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_client_random(&mut self, random: [u8; 32]) -> Result<(), PrfError> {
        let State::SessionKeys { client_random } = &mut self.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        *client_random = Some(random);
        Ok(())
    }

    /// Sets the server random.
    ///
    /// # Arguments
    ///
    /// * `random` - The server random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_server_random(&mut self, random: [u8; 32]) -> Result<(), PrfError> {
        let State::SessionKeys { client_random } = self.state.take() else {
            return Err(PrfError::state("PRF not set up"));
        };

        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        let client_random = client_random.expect("Client random should have been set by now");
        let server_random = random;

        let mut seed_ms = client_random.to_vec();
        seed_ms.extend_from_slice(&server_random);
        circuits.master_secret.set_start_seed(seed_ms);

        let mut seed_ke = server_random.to_vec();
        seed_ke.extend_from_slice(&client_random);
        circuits.key_expansion.set_start_seed(seed_ke);

        self.state = State::ClientFinished;
        Ok(())
    }

    /// Sets the client finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_cf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::ClientFinished = self.state.take() else {
            return Err(PrfError::state("PRF not in client finished state"));
        };

        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        let seed_cf = handshake_hash.to_vec();
        circuits.client_finished.set_start_seed(seed_cf);

        self.state = State::ServerFinished;
        Ok(())
    }

    /// Sets the server finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_sf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::ServerFinished = self.state.take() else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        let seed_sf = handshake_hash.to_vec();
        circuits.server_finished.set_start_seed(seed_sf);

        self.state = State::Complete;
        Ok(())
    }

    /// Drives the computation of the session keys.
    ///
    /// Returns if all inputs have been assigned for the computation of the
    /// final output.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    #[instrument(level = "debug", skip_all, err)]
    pub fn drive_key_expansion(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        circuits.drive_key_expansion(vm)
    }

    /// Drives the computation of the client_finished verify_data.
    ///
    /// Returns if all inputs have been assigned for the computation of the
    /// final output.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    #[instrument(level = "debug", skip_all, err)]
    pub fn drive_client_finished(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        circuits.drive_client_finished(vm)
    }

    /// Drives the computation of the server_finished verify_data.
    ///
    /// Returns if all inputs have been assigned for the computation of the
    /// final output.
    ///
    /// # Arguments
    ///
    /// * `vm` - Virtual machine.
    #[instrument(level = "debug", skip_all, err)]
    pub fn drive_server_finished(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        let Some(ref mut circuits) = self.circuits else {
            return Err(PrfError::state("Circuits should have been set for PRF"));
        };

        circuits.drive_server_finished(vm)
    }
}

/// Contains the respective [`PrfFunction`]s.
#[derive(Debug)]
struct Circuits {
    pub(crate) master_secret: Prf,
    pub(crate) key_expansion: Prf,
    pub(crate) client_finished: Prf,
    pub(crate) server_finished: Prf,
}

impl Circuits {
    const IPAD: [u8; 64] = [0x36; 64];
    const OPAD: [u8; 64] = [0x5c; 64];

    fn alloc(config: Config, vm: &mut dyn Vm<Binary>, pms: Vector<U8>) -> Result<Self, PrfError> {
        let outer_partial_pms = compute_partial(vm, pms, Self::OPAD)?;
        let inner_partial_pms = compute_partial(vm, pms, Self::IPAD)?;

        let master_secret =
            Prf::alloc_master_secret(config, vm, outer_partial_pms, inner_partial_pms)?;
        let ms = master_secret.output();
        let ms = merge_outputs(vm, ms, 48)?;

        let outer_partial_ms = compute_partial(vm, ms, Self::OPAD)?;
        let inner_partial_ms = compute_partial(vm, ms, Self::IPAD)?;

        let circuits = Self {
            master_secret,
            key_expansion: Prf::alloc_key_expansion(
                config,
                vm,
                outer_partial_ms,
                inner_partial_ms,
            )?,
            client_finished: Prf::alloc_client_finished(
                config,
                vm,
                outer_partial_ms,
                inner_partial_ms,
            )?,
            server_finished: Prf::alloc_server_finished(
                config,
                vm,
                outer_partial_ms,
                inner_partial_ms,
            )?,
        };
        Ok(circuits)
    }

    fn get_session_keys(&self, vm: &mut dyn Vm<Binary>) -> Result<SessionKeys, PrfError> {
        let keys = self.key_expansion.output();
        let mut keys = merge_outputs(vm, keys, 40)?;

        let server_iv = <Array<U8, 4> as FromRaw<Binary>>::from_raw(keys.split_off(36).to_raw());
        let client_iv = <Array<U8, 4> as FromRaw<Binary>>::from_raw(keys.split_off(32).to_raw());
        let server_write_key =
            <Array<U8, 16> as FromRaw<Binary>>::from_raw(keys.split_off(16).to_raw());
        let client_write_key = <Array<U8, 16> as FromRaw<Binary>>::from_raw(keys.to_raw());

        let session_keys = SessionKeys {
            client_write_key,
            server_write_key,
            client_iv,
            server_iv,
        };

        Ok(session_keys)
    }

    fn get_client_finished_vd(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 12>, PrfError> {
        let client_finished = &self.client_finished;
        let cf_vd = client_finished.output();

        let cf_vd = merge_outputs(vm, cf_vd, 12)?;
        let cf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(cf_vd.to_raw());

        Ok(cf_vd)
    }

    fn get_server_finished_vd(&self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 12>, PrfError> {
        let server_finished = &self.server_finished;
        let sf_vd = server_finished.output();

        let sf_vd = merge_outputs(vm, sf_vd, 12)?;
        let sf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(sf_vd.to_raw());

        Ok(sf_vd)
    }

    fn drive_key_expansion(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        let ms_finished = self.master_secret.make_progress(vm)?;
        let ke_finished = self.key_expansion.make_progress(vm)?;

        Ok(ms_finished && ke_finished)
    }

    fn drive_client_finished(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        self.client_finished.make_progress(vm)
    }

    fn drive_server_finished(&mut self, vm: &mut dyn Vm<Binary>) -> Result<bool, PrfError> {
        self.server_finished.make_progress(vm)
    }
}

/// Depending on the provided `mask` computes and returns `outer_partial` or
/// `inner_partial` for HMAC-SHA256.
///
/// # Arguments
///
/// * `vm` - Virtual machine.
/// * `key` - Key to pad and xor.
/// * `mask`- Mask used for padding.
fn compute_partial(
    vm: &mut dyn Vm<Binary>,
    key: Vector<U8>,
    mask: [u8; 64],
) -> Result<Array<U32, 8>, PrfError> {
    let xor = Arc::new(xor(8 * 64));

    let additional_len = 64 - key.len();
    let padding = vec![0_u8; additional_len];

    let padding_ref: Vector<U8> = vm.alloc_vec(additional_len).map_err(PrfError::vm)?;
    vm.mark_public(padding_ref).map_err(PrfError::vm)?;
    vm.assign(padding_ref, padding).map_err(PrfError::vm)?;
    vm.commit(padding_ref).map_err(PrfError::vm)?;

    let mask_ref: Array<U8, 64> = vm.alloc().map_err(PrfError::vm)?;
    vm.mark_public(mask_ref).map_err(PrfError::vm)?;
    vm.assign(mask_ref, mask).map_err(PrfError::vm)?;
    vm.commit(mask_ref).map_err(PrfError::vm)?;

    let xor = Call::builder(xor)
        .arg(key)
        .arg(padding_ref)
        .arg(mask_ref)
        .build()
        .map_err(PrfError::vm)?;
    let key_padded = vm.call(xor).map_err(PrfError::vm)?;

    let mut sha = Sha256::default();
    sha.update(key_padded);
    sha.alloc(vm)
}

fn merge_outputs(
    vm: &mut dyn Vm<Binary>,
    inputs: Vec<Array<U32, 8>>,
    output_bytes: usize,
) -> Result<Vector<U8>, PrfError> {
    assert!(output_bytes <= 32 * inputs.len());

    let bits = Array::<U32, 8>::SIZE * inputs.len();
    let msb0_circ = gen_merge_circ(4, bits);

    let mut builder = Call::builder(msb0_circ);
    for &input in inputs.iter() {
        builder = builder.arg(input);
    }
    let call = builder.build().map_err(PrfError::vm)?;

    let mut output: Vector<U8> = vm.call(call).map_err(PrfError::vm)?;
    output.truncate(output_bytes);
    Ok(output)
}

fn gen_merge_circ(element_byte_size: usize, size: usize) -> Arc<Circuit> {
    assert!((size / 8) % element_byte_size == 0);

    let mut builder = CircuitBuilder::new();
    let inputs = (0..size).map(|_| builder.add_input()).collect::<Vec<_>>();

    for input in inputs.chunks_exact(element_byte_size * 8) {
        for byte in input.chunks_exact(8).rev() {
            for &feed in byte.iter() {
                let output = builder.add_id_gate(feed);
                builder.add_output(output);
            }
        }
    }

    Arc::new(builder.build().expect("merge circuit is valid"))
}

#[cfg(test)]
mod tests {
    use crate::{convert_to_bytes, prf::merge_outputs, test_utils::mock_vm};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U32, Array, MemoryExt, ViewExt},
        Execute,
    };

    #[tokio::test]
    async fn test_merge_outputs() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        let input1: [u32; 8] = std::array::from_fn(|i| i as u32);
        let input2: [u32; 8] = std::array::from_fn(|i| i as u32 + 8);

        let mut expected = convert_to_bytes(input1).to_vec();
        expected.extend_from_slice(&convert_to_bytes(input2));
        expected.truncate(48);

        // leader
        let input1_leader: Array<U32, 8> = leader.alloc().unwrap();
        let input2_leader: Array<U32, 8> = leader.alloc().unwrap();

        leader.mark_public(input1_leader).unwrap();
        leader.mark_public(input2_leader).unwrap();

        leader.assign(input1_leader, input1).unwrap();
        leader.assign(input2_leader, input2).unwrap();

        leader.commit(input1_leader).unwrap();
        leader.commit(input2_leader).unwrap();

        let merged_leader =
            merge_outputs(&mut leader, vec![input1_leader, input2_leader], 48).unwrap();
        let mut merged_leader = leader.decode(merged_leader).unwrap();

        // follower
        let input1_follower: Array<U32, 8> = follower.alloc().unwrap();
        let input2_follower: Array<U32, 8> = follower.alloc().unwrap();

        follower.mark_public(input1_follower).unwrap();
        follower.mark_public(input2_follower).unwrap();

        follower.assign(input1_follower, input1).unwrap();
        follower.assign(input2_follower, input2).unwrap();

        follower.commit(input1_follower).unwrap();
        follower.commit(input2_follower).unwrap();

        let merged_follower =
            merge_outputs(&mut follower, vec![input1_follower, input2_follower], 48).unwrap();
        let mut merged_follower = follower.decode(merged_follower).unwrap();

        tokio::try_join!(
            leader.execute_all(&mut ctx_a),
            follower.execute_all(&mut ctx_b)
        )
        .unwrap();

        let merged_leader = merged_leader.try_recv().unwrap().unwrap();
        let merged_follower = merged_follower.try_recv().unwrap().unwrap();

        assert_eq!(merged_leader, merged_follower);
        assert_eq!(merged_leader, expected);
    }
}
