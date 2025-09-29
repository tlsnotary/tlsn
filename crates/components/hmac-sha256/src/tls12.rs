//! Functionality for computing HMAC-SHA-256-based TLS 1.2 PRF.

use std::{fmt::Debug, sync::Arc};

use mpz_circuits::{Circuit, CircuitBuilder};
use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, StaticSize, Vector,
    },
    Call, CallableExt, Vm,
};
use tracing::instrument;

use crate::{hmac::Hmac, prf::Prf, tls12::state::State, FError, Mode};

mod state;

/// Functionality for computing HMAC-SHA-256-based TLS 1.2 PRF.
#[derive(Debug)]
pub struct Tls12Prf {
    mode: Mode,
    state: State,
}

impl Tls12Prf {
    /// Creates a new instance of the PRF.
    ///
    /// # Arguments
    ///
    /// `mode` - The PRF mode.
    pub fn new(mode: Mode) -> Tls12Prf {
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
    ) -> Result<PrfOutput, FError> {
        let State::Initialized = self.state.take() else {
            return Err(FError::state("PRF not in initialized state"));
        };

        let mode = self.mode;

        let hmac_pms = Hmac::alloc(vm, pms.into(), mode)?;

        let master_secret = Prf::alloc_master_secret(mode, vm, hmac_pms)?;

        let hmac_ms1: Hmac = Hmac::alloc(vm, master_secret.output(), mode)?;
        let hmac_ms2 = Hmac::from_other(vm, &hmac_ms1)?;
        let hmac_ms3 = Hmac::from_other(vm, &hmac_ms1)?;

        let key_expansion = Prf::alloc_key_expansion(mode, vm, hmac_ms1)?;

        let client_finished = Prf::alloc_client_finished(mode, vm, hmac_ms2)?;

        let server_finished = Prf::alloc_server_finished(mode, vm, hmac_ms3)?;

        self.state = State::SessionKeys {
            client_random: None,
            master_secret,
            key_expansion,
            client_finished,
            server_finished,
        };

        self.state.prf_output()
    }

    /// Sets the client random.
    ///
    /// # Arguments
    ///
    /// * `random` - The client random.
    #[instrument(level = "debug", skip_all, err)]
    pub fn set_client_random(&mut self, random: [u8; 32]) -> Result<(), FError> {
        let State::SessionKeys { client_random, .. } = &mut self.state else {
            return Err(FError::state("PRF not set up"));
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
    pub fn set_server_random(&mut self, random: [u8; 32]) -> Result<(), FError> {
        let State::SessionKeys {
            client_random,
            master_secret,
            key_expansion,
            ..
        } = &mut self.state
        else {
            return Err(FError::state("PRF not set up"));
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
    pub fn set_cf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), FError> {
        let State::ClientFinished {
            client_finished, ..
        } = &mut self.state
        else {
            return Err(FError::state("PRF not in client finished state"));
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
    pub fn set_sf_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), FError> {
        let State::ServerFinished { server_finished } = &mut self.state else {
            return Err(FError::state("PRF not in server finished state"));
        };

        let seed_sf = handshake_hash.to_vec();
        server_finished.set_start_seed(seed_sf);

        Ok(())
    }

    /// Returns if the PRF needs to be flushed.
    pub fn wants_flush(&self) -> bool {
        match &self.state {
            State::SessionKeys {
                master_secret,
                key_expansion,
                ..
            } => master_secret.wants_flush() || key_expansion.wants_flush(),
            State::ClientFinished {
                client_finished, ..
            } => client_finished.wants_flush(),
            State::ServerFinished { server_finished } => server_finished.wants_flush(),
            _ => false,
        }
    }

    /// Flushes the PRF.
    pub fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        self.state = match self.state.take() {
            State::SessionKeys {
                client_random,
                mut master_secret,
                mut key_expansion,
                client_finished,
                server_finished,
            } => {
                master_secret.flush(vm)?;
                key_expansion.flush(vm)?;

                if master_secret.is_complete() && key_expansion.is_complete() {
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

                if client_finished.is_complete() {
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

                if server_finished.is_complete() {
                    State::Complete
                } else {
                    State::ServerFinished { server_finished }
                }
            }
            other => other,
        };

        Ok(())
    }
}

/// PRF output.
#[derive(Debug, Clone, Copy)]
pub struct PrfOutput {
    /// TLS session keys.
    pub keys: SessionKeys,
    /// Client finished verify data.
    pub cf_vd: Array<U8, 12>,
    /// Server finished verify data.
    pub sf_vd: Array<U8, 12>,
}

/// Session keys computed by the PRF.
#[derive(Debug, Clone, Copy)]
pub struct SessionKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Client IV.
    pub client_iv: Array<U8, 4>,
    /// Server IV.
    pub server_iv: Array<U8, 4>,
}

/// Merges vectors, returning the merged vector truncated to the `output_bytes`
/// length.
pub(crate) fn merge_vectors(
    vm: &mut dyn Vm<Binary>,
    inputs: Vec<Vector<U8>>,
    output_bytes: usize,
) -> Result<Vector<U8>, FError> {
    let len = inputs.iter().map(|inp| inp.len()).sum();
    assert!(output_bytes <= len);

    let bits = len * U8::SIZE;
    let circ = gen_merge_circ(bits);

    let mut builder = Call::builder(circ);
    for &input in inputs.iter() {
        builder = builder.arg(input);
    }
    let call = builder.build().map_err(FError::vm)?;

    let mut output: Vector<U8> = vm.call(call).map_err(FError::vm)?;
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
    use crate::{
        test_utils::{mock_vm, prf_cf_vd, prf_keys, prf_ms, prf_sf_vd},
        tls12::merge_vectors,
        Mode, SessionKeys, Tls12Prf,
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::U8, Array, MemoryExt, Vector, ViewExt},
        Execute,
    };
    use rand::{rngs::StdRng, Rng, SeedableRng};
    use rstest::*;

    #[rstest]
    #[case::normal(Mode::Normal)]
    #[case::reduced(Mode::Reduced)]
    #[tokio::test]
    async fn test_tls12prf(#[case] mode: Mode) {
        let mut rng = StdRng::seed_from_u64(1);
        // Test input.
        let pms: [u8; 32] = rng.random();
        let client_random: [u8; 32] = rng.random();
        let server_random: [u8; 32] = rng.random();

        let cf_hs_hash: [u8; 32] = rng.random();
        let sf_hs_hash: [u8; 32] = rng.random();

        // Expected output.
        let ms_expected = prf_ms(pms, client_random, server_random);

        let [cwk_expected, swk_expected, civ_expected, siv_expected] =
            prf_keys(ms_expected, client_random, server_random);

        let cwk_expected: [u8; 16] = cwk_expected.try_into().unwrap();
        let swk_expected: [u8; 16] = swk_expected.try_into().unwrap();
        let civ_expected: [u8; 4] = civ_expected.try_into().unwrap();
        let siv_expected: [u8; 4] = siv_expected.try_into().unwrap();

        let cf_vd_expected = prf_cf_vd(ms_expected, cf_hs_hash);
        let sf_vd_expected = prf_sf_vd(ms_expected, sf_hs_hash);

        let cf_vd_expected: [u8; 12] = cf_vd_expected.try_into().unwrap();
        let sf_vd_expected: [u8; 12] = sf_vd_expected.try_into().unwrap();

        // Set up vm and prf.
        let (mut ctx_a, mut ctx_b) = test_st_context(128);
        let (mut leader, mut follower) = mock_vm();

        let leader_pms: Array<U8, 32> = leader.alloc().unwrap();
        leader.mark_public(leader_pms).unwrap();
        leader.assign(leader_pms, pms).unwrap();
        leader.commit(leader_pms).unwrap();

        let follower_pms: Array<U8, 32> = follower.alloc().unwrap();
        follower.mark_public(follower_pms).unwrap();
        follower.assign(follower_pms, pms).unwrap();
        follower.commit(follower_pms).unwrap();

        let mut prf_leader = Tls12Prf::new(mode);
        let mut prf_follower = Tls12Prf::new(mode);

        let leader_prf_out = prf_leader.alloc(&mut leader, leader_pms).unwrap();
        let follower_prf_out = prf_follower.alloc(&mut follower, follower_pms).unwrap();

        // client_random and server_random.
        prf_leader.set_client_random(client_random).unwrap();
        prf_follower.set_client_random(client_random).unwrap();

        prf_leader.set_server_random(server_random).unwrap();
        prf_follower.set_server_random(server_random).unwrap();

        let SessionKeys {
            client_write_key: cwk_leader,
            server_write_key: swk_leader,
            client_iv: civ_leader,
            server_iv: siv_leader,
        } = leader_prf_out.keys;

        let mut cwk_leader = leader.decode(cwk_leader).unwrap();
        let mut swk_leader = leader.decode(swk_leader).unwrap();
        let mut civ_leader = leader.decode(civ_leader).unwrap();
        let mut siv_leader = leader.decode(siv_leader).unwrap();

        let SessionKeys {
            client_write_key: cwk_follower,
            server_write_key: swk_follower,
            client_iv: civ_follower,
            server_iv: siv_follower,
        } = follower_prf_out.keys;

        let mut cwk_follower = follower.decode(cwk_follower).unwrap();
        let mut swk_follower = follower.decode(swk_follower).unwrap();
        let mut civ_follower = follower.decode(civ_follower).unwrap();
        let mut siv_follower = follower.decode(siv_follower).unwrap();

        while prf_leader.wants_flush() || prf_follower.wants_flush() {
            tokio::try_join!(
                async {
                    prf_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await
                },
                async {
                    prf_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await
                }
            )
            .unwrap();
        }

        let cwk_leader = cwk_leader.try_recv().unwrap().unwrap();
        let swk_leader = swk_leader.try_recv().unwrap().unwrap();
        let civ_leader = civ_leader.try_recv().unwrap().unwrap();
        let siv_leader = siv_leader.try_recv().unwrap().unwrap();

        let cwk_follower = cwk_follower.try_recv().unwrap().unwrap();
        let swk_follower = swk_follower.try_recv().unwrap().unwrap();
        let civ_follower = civ_follower.try_recv().unwrap().unwrap();
        let siv_follower = siv_follower.try_recv().unwrap().unwrap();

        assert_eq!(cwk_leader, cwk_follower);
        assert_eq!(swk_leader, swk_follower);
        assert_eq!(civ_leader, civ_follower);
        assert_eq!(siv_leader, siv_follower);

        assert_eq!(cwk_leader, cwk_expected);
        assert_eq!(swk_leader, swk_expected);
        assert_eq!(civ_leader, civ_expected);
        assert_eq!(siv_leader, siv_expected);

        // client finished.
        prf_leader.set_cf_hash(cf_hs_hash).unwrap();
        prf_follower.set_cf_hash(cf_hs_hash).unwrap();

        let cf_vd_leader = leader_prf_out.cf_vd;
        let cf_vd_follower = follower_prf_out.cf_vd;

        let mut cf_vd_leader = leader.decode(cf_vd_leader).unwrap();
        let mut cf_vd_follower = follower.decode(cf_vd_follower).unwrap();

        while prf_leader.wants_flush() || prf_follower.wants_flush() {
            tokio::try_join!(
                async {
                    prf_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await
                },
                async {
                    prf_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await
                }
            )
            .unwrap();
        }

        let cf_vd_leader = cf_vd_leader.try_recv().unwrap().unwrap();
        let cf_vd_follower = cf_vd_follower.try_recv().unwrap().unwrap();

        assert_eq!(cf_vd_leader, cf_vd_follower);
        assert_eq!(cf_vd_leader, cf_vd_expected);

        // server finished.
        prf_leader.set_sf_hash(sf_hs_hash).unwrap();
        prf_follower.set_sf_hash(sf_hs_hash).unwrap();

        let sf_vd_leader = leader_prf_out.sf_vd;
        let sf_vd_follower = follower_prf_out.sf_vd;

        let mut sf_vd_leader = leader.decode(sf_vd_leader).unwrap();
        let mut sf_vd_follower = follower.decode(sf_vd_follower).unwrap();

        while prf_leader.wants_flush() || prf_follower.wants_flush() {
            tokio::try_join!(
                async {
                    prf_leader.flush(&mut leader).unwrap();
                    leader.execute_all(&mut ctx_a).await
                },
                async {
                    prf_follower.flush(&mut follower).unwrap();
                    follower.execute_all(&mut ctx_b).await
                }
            )
            .unwrap();
        }

        let sf_vd_leader = sf_vd_leader.try_recv().unwrap().unwrap();
        let sf_vd_follower = sf_vd_follower.try_recv().unwrap().unwrap();

        assert_eq!(sf_vd_leader, sf_vd_follower);
        assert_eq!(sf_vd_leader, sf_vd_expected);
    }

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
        let input1_leader: Vector<U8> = leader.alloc_vec(32).unwrap();
        let input2_leader: Vector<U8> = leader.alloc_vec(32).unwrap();

        leader.mark_public(input1_leader).unwrap();
        leader.mark_public(input2_leader).unwrap();

        leader.assign(input1_leader, input1.to_vec()).unwrap();
        leader.assign(input2_leader, input2.to_vec()).unwrap();

        leader.commit(input1_leader).unwrap();
        leader.commit(input2_leader).unwrap();

        let merged_leader =
            merge_vectors(&mut leader, vec![input1_leader, input2_leader], 48).unwrap();
        let mut merged_leader = leader.decode(merged_leader).unwrap();

        // follower
        let input1_follower: Vector<U8> = follower.alloc_vec(32).unwrap();
        let input2_follower: Vector<U8> = follower.alloc_vec(32).unwrap();

        follower.mark_public(input1_follower).unwrap();
        follower.mark_public(input2_follower).unwrap();

        follower.assign(input1_follower, input1.to_vec()).unwrap();
        follower.assign(input2_follower, input2.to_vec()).unwrap();

        follower.commit(input1_follower).unwrap();
        follower.commit(input2_follower).unwrap();

        let merged_follower =
            merge_vectors(&mut follower, vec![input1_follower, input2_follower], 48).unwrap();
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
