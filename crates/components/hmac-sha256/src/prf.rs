use crate::{
    hmac::{IPAD, OPAD},
    Mode, PrfError, PrfOutput,
};
use mpz_circuits::{circuits::xor, Circuit, CircuitBuilder};
use mpz_hash::sha256::Sha256;
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, MemoryExt, StaticSize, Vector, ViewExt,
    },
    Call, CallableExt, Vm,
};
use std::{fmt::Debug, sync::Arc};
use tracing::instrument;

mod state;
use state::State;

mod function;
use function::Prf;

/// MPC PRF for computing TLS 1.2 HMAC-SHA256 PRF.
#[derive(Debug)]
pub struct MpcPrf {
    mode: Mode,
    state: State,
}

impl MpcPrf {
    /// Creates a new instance of the PRF.
    ///
    /// # Arguments
    ///
    /// `mode` - The PRF mode.
    pub fn new(mode: Mode) -> MpcPrf {
        Self {
            mode,
            state: State::Initialized,
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

        let mode = self.mode;
        let pms: Vector<U8> = pms.into();

        let outer_partial_pms = compute_partial(vm, pms, OPAD)?;
        let inner_partial_pms = compute_partial(vm, pms, IPAD)?;

        let master_secret =
            Prf::alloc_master_secret(mode, vm, outer_partial_pms, inner_partial_pms)?;
        let ms = master_secret.output();
        let ms = merge_outputs(vm, ms, 48)?;

        let outer_partial_ms = compute_partial(vm, ms, OPAD)?;
        let inner_partial_ms = compute_partial(vm, ms, IPAD)?;

        let key_expansion =
            Prf::alloc_key_expansion(mode, vm, outer_partial_ms.clone(), inner_partial_ms.clone())?;
        let client_finished = Prf::alloc_client_finished(
            mode,
            vm,
            outer_partial_ms.clone(),
            inner_partial_ms.clone(),
        )?;
        let server_finished = Prf::alloc_server_finished(
            mode,
            vm,
            outer_partial_ms.clone(),
            inner_partial_ms.clone(),
        )?;

        self.state = State::SessionKeys {
            client_random: None,
            master_secret,
            key_expansion,
            client_finished,
            server_finished,
        };

        self.state.prf_output(vm)
    }

    /// Sets the client random.
    ///
    /// # Arguments
    ///
    /// * `random` - The client random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_client_random(&mut self, random: [u8; 32]) -> Result<(), PrfError> {
        let State::SessionKeys { client_random, .. } = &mut self.state else {
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
        let State::SessionKeys {
            client_random,
            master_secret,
            key_expansion,
            ..
        } = &mut self.state
        else {
            return Err(PrfError::state("PRF not set up"));
        };

        let client_random = client_random.expect("Client random should have been set by now");
        let server_random = random;

        let mut seed_ms = client_random.to_vec();
        seed_ms.extend_from_slice(&server_random);
        master_secret.set_start_seed(seed_ms);

        let mut seed_ke = server_random.to_vec();
        seed_ke.extend_from_slice(&client_random);
        key_expansion.set_start_seed(seed_ke);

        Ok(())
    }

    /// Sets the client finished handshake hash.
    ///
    /// # Arguments
    ///
    /// * `handshake_hash` - The handshake transcript hash.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_cf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), PrfError> {
        let State::ClientFinished {
            client_finished, ..
        } = &mut self.state
        else {
            return Err(PrfError::state("PRF not in client finished state"));
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
        let State::ServerFinished { server_finished } = &mut self.state else {
            return Err(PrfError::state("PRF not in server finished state"));
        };

        let seed_sf = handshake_hash.to_vec();
        server_finished.set_start_seed(seed_sf);

        Ok(())
    }

    /// Returns if the PRF needs to be flushed.
    pub fn wants_flush(&self) -> bool {
        match &self.state {
            State::Initialized => false,
            State::SessionKeys {
                master_secret,
                key_expansion,
                ..
            } => master_secret.wants_flush() || key_expansion.wants_flush(),
            State::ClientFinished {
                client_finished, ..
            } => client_finished.wants_flush(),
            State::ServerFinished { server_finished } => server_finished.wants_flush(),
            State::Complete => false,
            State::Error => false,
        }
    }

    /// Flushes the PRF.
    pub fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), PrfError> {
        let state = match self.state.take() {
            State::SessionKeys {
                client_random,
                mut master_secret,
                mut key_expansion,
                client_finished,
                server_finished,
            } => {
                master_secret.flush(vm)?;
                key_expansion.flush(vm)?;

                if !master_secret.wants_flush() && !key_expansion.wants_flush() {
                    State::ClientFinished {
                        client_finished,
                        server_finished,
                    }
                } else {
                    State::SessionKeys {
                        client_random,
                        master_secret,
                        key_expansion,
                        client_finished,
                        server_finished,
                    }
                }
            }
            State::ClientFinished {
                mut client_finished,
                server_finished,
            } => {
                client_finished.flush(vm)?;

                if !client_finished.wants_flush() {
                    State::ServerFinished { server_finished }
                } else {
                    State::ClientFinished {
                        client_finished,
                        server_finished,
                    }
                }
            }
            State::ServerFinished {
                mut server_finished,
            } => {
                server_finished.flush(vm)?;

                if !server_finished.wants_flush() {
                    State::Complete
                } else {
                    State::ServerFinished { server_finished }
                }
            }
            other => other,
        };

        self.state = state;
        Ok(())
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
    use crate::{prf::merge_outputs, test_utils::mock_vm};
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, ViewExt},
        Execute,
    };

    #[tokio::test]
    async fn test_merge_outputs() {
        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

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
