use crate::{
    hmac::{IPAD, OPAD},
    MSMode, PrfConfig, PrfError, PrfOutput, SessionKeys,
};
use mpz_circuits::{circuits::xor, Circuit, CircuitBuilder};
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, FromRaw, MemoryExt, StaticSize, ToRaw, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};
use std::{fmt::Debug, sync::Arc};
use tracing::instrument;

mod function;
use function::InnerPrf;

/// PRF for computing TLS 1.2 HMAC-SHA256 PRF.
#[derive(Debug)]
pub struct Prf {
    config: PrfConfig,
    state: State,
    client_random: Option<[u8; 32]>,
}

#[derive(Debug)]
pub(crate) enum State {
    Initialized,
    Setup {
        master_secret: Box<InnerPrf>,
        key_expansion: Box<InnerPrf>,
        client_finished: Box<InnerPrf>,
        server_finished: Box<InnerPrf>,
    },
    Complete,
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}

impl Prf {
    /// Creates a new instance of the PRF.
    ///
    /// # Arguments
    ///
    /// * `config` - The PRF configuration.
    pub fn new(config: PrfConfig) -> Prf {
        Self {
            config,
            state: State::Initialized,
            client_random: None,
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

        let pms: Vector<U8> = pms.into();

        let outer_partial_pms = compute_partial(vm, pms, OPAD)?;
        let inner_partial_pms = compute_partial(vm, pms, IPAD)?;

        let master_secret =
            InnerPrf::alloc_master_secret(self.config, vm, outer_partial_pms, inner_partial_pms)?;
        let ms = master_secret.output();
        let ms = merge_outputs(vm, ms, 48)?;

        let outer_partial_ms = compute_partial(vm, ms, OPAD)?;
        let inner_partial_ms = compute_partial(vm, ms, IPAD)?;

        let key_expansion = InnerPrf::alloc_key_expansion(
            self.config.network,
            vm,
            outer_partial_ms.clone(),
            inner_partial_ms.clone(),
        )?;
        let client_finished = InnerPrf::alloc_client_finished(
            self.config.network,
            vm,
            outer_partial_ms.clone(),
            inner_partial_ms.clone(),
        )?;
        let server_finished = InnerPrf::alloc_server_finished(
            self.config.network,
            vm,
            outer_partial_ms.clone(),
            inner_partial_ms.clone(),
        )?;

        let keys = get_session_keys(key_expansion.output(), vm)?;
        let cf_vd = get_client_finished_vd(client_finished.output(), vm)?;
        let sf_vd = get_server_finished_vd(server_finished.output(), vm)?;

        let output = PrfOutput { keys, cf_vd, sf_vd };

        self.state = State::Setup {
            master_secret: Box::new(master_secret),
            key_expansion: Box::new(key_expansion),
            client_finished: Box::new(client_finished),
            server_finished: Box::new(server_finished),
        };

        Ok(output)
    }

    /// Sets the client random.
    ///
    /// # Arguments
    ///
    /// * `random` - The client random.
    #[instrument(level = "debug", skip_all)]
    pub fn set_client_random(&mut self, random: [u8; 32]) {
        self.client_random = Some(random);
    }

    /// Sets the server random.
    ///
    /// # Arguments
    ///
    /// * `random` - The server random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_server_random(&mut self, random: [u8; 32]) -> Result<(), PrfError> {
        let State::Setup {
            master_secret,
            key_expansion,
            ..
        } = &mut self.state
        else {
            return Err(PrfError::state("PRF not set up"));
        };

        let client_random = self
            .client_random
            .expect("Client random should have been set by now");
        let server_random = random;

        if matches!(self.config.ms, MSMode::Standard) {
            let mut seed_ms = client_random.to_vec();
            seed_ms.extend_from_slice(&server_random);
            master_secret.set_start_seed(seed_ms);
        }

        let mut seed_ke = server_random.to_vec();
        seed_ke.extend_from_slice(&client_random);
        key_expansion.set_start_seed(seed_ke);

        Ok(())
    }

    /// Sets the session hash.
    ///
    /// This is used for Extended Master Secret (RFC 7627).
    ///
    /// # Arguments
    ///
    /// * `seed` - The session hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_session_hash(&mut self, seed: Vec<u8>) -> Result<(), PrfError> {
        let State::Setup { master_secret, .. } = &mut self.state else {
            return Err(PrfError::state("PRF not set up"));
        };

        if !matches!(self.config.ms, MSMode::Extended) {
            return Err(PrfError::config(
                "session hash should only be set in EMS mode",
            ));
        }

        master_secret.set_start_seed(seed);
        Ok(())
    }

    /// Sets the client finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_cf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::Setup {
            client_finished, ..
        } = &mut self.state
        else {
            return Err(PrfError::state("PRF not setup"));
        };

        let seed_cf = handshake_hash.to_vec();
        client_finished.set_start_seed(seed_cf);

        Ok(())
    }

    /// Sets the server finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_sf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::Setup {
            server_finished, ..
        } = &mut self.state
        else {
            return Err(PrfError::state("PRF not setup"));
        };

        let seed_sf = handshake_hash.to_vec();
        server_finished.set_start_seed(seed_sf);

        Ok(())
    }

    /// Returns if the PRF needs to be flushed.
    pub fn wants_flush(&self) -> bool {
        match &self.state {
            State::Initialized => false,
            State::Setup {
                master_secret,
                key_expansion,
                client_finished,
                server_finished,
            } => {
                master_secret.wants_flush()
                    || key_expansion.wants_flush()
                    || client_finished.wants_flush()
                    || server_finished.wants_flush()
            }
            State::Complete => false,
            State::Error => false,
        }
    }

    /// Flushes the PRF.
    pub fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        self.state = match self.state.take() {
            State::Setup {
                mut master_secret,
                mut key_expansion,
                mut client_finished,
                mut server_finished,
            } => {
                if master_secret.wants_flush() {
                    master_secret.flush(vm)?;
                }
                if key_expansion.wants_flush() {
                    key_expansion.flush(vm)?;
                }
                if client_finished.wants_flush() {
                    client_finished.flush(vm)?;
                }
                if server_finished.wants_flush() {
                    server_finished.flush(vm)?;
                }

                if master_secret.is_done()
                    && key_expansion.is_done()
                    && client_finished.is_done()
                    && server_finished.is_done()
                {
                    State::Complete
                } else {
                    State::Setup {
                        master_secret,
                        key_expansion,
                        client_finished,
                        server_finished,
                    }
                }
            }
            other => other,
        };

        Ok(())
    }
}

fn get_session_keys(
    output: Vec<Array<U8, 32>>,
    vm: &mut dyn Vm<Binary>,
) -> Result<SessionKeys, PrfError> {
    let mut keys = merge_outputs(vm, output, 40)?;
    debug_assert!(keys.len() == 40, "session keys len should be 40");

    let server_iv = Array::<U8, 4>::try_from(keys.split_off(36)).unwrap();
    let client_iv = Array::<U8, 4>::try_from(keys.split_off(32)).unwrap();
    let server_write_key = Array::<U8, 16>::try_from(keys.split_off(16)).unwrap();
    let client_write_key = Array::<U8, 16>::try_from(keys).unwrap();

    let session_keys = SessionKeys {
        client_write_key,
        server_write_key,
        client_iv,
        server_iv,
    };

    Ok(session_keys)
}

fn get_client_finished_vd(
    output: Vec<Array<U8, 32>>,
    vm: &mut dyn Vm<Binary>,
) -> Result<Array<U8, 12>, PrfError> {
    let cf_vd = merge_outputs(vm, output, 12)?;
    let cf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(cf_vd.to_raw());

    Ok(cf_vd)
}

fn get_server_finished_vd(
    output: Vec<Array<U8, 32>>,
    vm: &mut dyn Vm<Binary>,
) -> Result<Array<U8, 12>, PrfError> {
    let sf_vd = merge_outputs(vm, output, 12)?;
    let sf_vd = <Array<U8, 12> as FromRaw<Binary>>::from_raw(sf_vd.to_raw());

    Ok(sf_vd)
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
) -> Result<Sha256, PrfError> {
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
    let key_padded: Vector<U8> = vm.call(xor).map_err(PrfError::vm)?;

    let mut sha = Sha256::new_with_init(vm)?;
    sha.update(&key_padded);
    sha.compress(vm)?;
    Ok(sha)
}

fn merge_outputs(
    vm: &mut dyn Vm<Binary>,
    inputs: Vec<Array<U8, 32>>,
    output_bytes: usize,
) -> Result<Vector<U8>, PrfError> {
    assert!(output_bytes <= 32 * inputs.len());

    let bits = Array::<U8, 32>::SIZE * inputs.len();
    let circ = gen_merge_circ(bits);

    let mut builder = Call::builder(circ);
    for &input in inputs.iter() {
        builder = builder.arg(input);
    }
    let call = builder.build().map_err(PrfError::vm)?;

    let mut output: Vector<U8> = vm.call(call).map_err(PrfError::vm)?;
    output.truncate(output_bytes);
    Ok(output)
}

fn gen_merge_circ(size: usize) -> Arc<Circuit> {
    let mut builder = CircuitBuilder::new();
    let inputs = (0..size).map(|_| builder.add_input()).collect::<Vec<_>>();

    for input in inputs.chunks_exact(8) {
        for byte in input.chunks_exact(8) {
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
    use crate::prf::merge_outputs;
    use mpz_common::context::test_st_context;
    use mpz_ideal_vm::IdealVm;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };

    #[tokio::test]
    async fn test_merge_outputs() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let mut leader = IdealVm::new();
        let mut follower = IdealVm::new();

        let input1: [u8; 32] = std::array::from_fn(|i| i as u8);
        let input2: [u8; 32] = std::array::from_fn(|i| i as u8 + 32);

        let mut expected = input1.to_vec();
        expected.extend_from_slice(&input2);
        expected.truncate(48);

        // leader
        let input1_leader: Array<U8, 32> = leader.alloc().unwrap();
        let input2_leader: Array<U8, 32> = leader.alloc().unwrap();

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
        let input1_follower: Array<U8, 32> = follower.alloc().unwrap();
        let input2_follower: Array<U8, 32> = follower.alloc().unwrap();

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
