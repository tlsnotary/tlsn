//! Functionality for computing HMAC-SHA256-based TLS 1.3 key schedule.

use std::mem;

use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Array, MemoryExt,
    },
    OneTimePad, Vm,
};
use rand::RngCore;

use crate::{
    hmac::Hmac,
    kdf::{expand::hkdf_expand_label, extract::HkdfExtract},
    tls13::{application::ApplicationSecrets, handshake::HandshakeSecrets},
    FError, Mode,
};

mod application;
mod handshake;

/// Functionality role.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Role {
    /// Leader.
    ///
    /// The leader learns handshake secrets and locally finishes the handshake.
    Leader,
    /// Follower.
    Follower,
}

/// Functionality for computing HMAC-SHA-256-based TLS 1.3 key schedule.
pub struct Tls13KeySched {
    mode: Mode,
    role: Role,
    // Allocated master secret.
    master_secret: Option<HkdfExtract>,
    // Allocated application secrets.
    application: Option<ApplicationSecrets>,
    state: State,
}

impl Tls13KeySched {
    /// Creates a new functionality.
    pub fn new(mode: Mode, role: Role) -> Tls13KeySched {
        Self {
            mode,
            role,
            application: None,
            master_secret: None,
            state: State::Initialized,
        }
    }

    /// Allocates the functionality with the given pre-master secret.
    pub fn alloc(&mut self, vm: &mut dyn Vm<Binary>, pms: Array<U8, 32>) -> Result<(), FError> {
        let State::Initialized = self.state.take() else {
            return Err(FError::state("not in initialized state"));
        };

        let mut hs_secrets = HandshakeSecrets::new(self.mode);
        let (cs, ss, derived_secret) = hs_secrets.alloc(vm, pms)?;

        let (masked_cs, cs_otp, masked_ss, ss_otp) = match self.role {
            Role::Leader => {
                let mut cs_otp = [0u8; 32];
                let mut ss_otp = [0u8; 32];
                rand::rng().fill_bytes(&mut cs_otp);
                rand::rng().fill_bytes(&mut ss_otp);
                let masked_cs = vm.mask_private(cs, cs_otp).map_err(FError::vm)?;
                let masked_ss = vm.mask_private(ss, ss_otp).map_err(FError::vm)?;
                (masked_cs, Some(cs_otp), masked_ss, Some(ss_otp))
            }
            Role::Follower => {
                let masked_cs = vm.mask_blind(cs).map_err(FError::vm)?;
                let masked_ss = vm.mask_blind(ss).map_err(FError::vm)?;
                (masked_cs, None, masked_ss, None)
            }
        };

        // Decode as soon as values are known.
        std::mem::drop(vm.decode(masked_cs).map_err(FError::vm)?);
        std::mem::drop(vm.decode(masked_ss).map_err(FError::vm)?);

        let hmac_derived = Hmac::alloc(vm, derived_secret, self.mode)?;
        let master_secret = HkdfExtract::alloc(self.mode, vm, [0u8; 32], hmac_derived)?;

        let mut aps = ApplicationSecrets::new(self.mode);
        aps.alloc(vm, master_secret.output())?;

        self.master_secret = Some(master_secret);
        self.application = Some(aps);
        self.state = State::Handshake {
            secrets: hs_secrets,
            masked_cs,
            masked_ss,
            cs_otp,
            ss_otp,
        };

        Ok(())
    }

    /// Whether this functionality needs to be flushed.
    pub fn wants_flush(&self) -> bool {
        match &self.state {
            State::Handshake { secrets, .. } => secrets.wants_flush(),
            State::WantsDecodedKeys { .. } => true,
            State::MasterSecret(ms) => ms.wants_flush(),
            State::Application(app) => app.wants_flush(),
            _ => false,
        }
    }

    /// Flushes the functionality.
    pub fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        match &mut self.state {
            State::Handshake { secrets, .. } => {
                secrets.flush(vm)?;

                if secrets.is_complete() {
                    match self.state.take() {
                        State::Handshake {
                            masked_cs,
                            masked_ss,
                            cs_otp,
                            ss_otp,
                            ..
                        } => {
                            self.state = State::WantsDecodedKeys {
                                masked_cs,
                                masked_ss,
                                cs_otp,
                                ss_otp,
                            };
                            // Recurse.
                            self.flush(vm)?;
                            return Ok(());
                        }
                        _ => unreachable!(),
                    }
                }
            }
            State::WantsDecodedKeys {
                masked_cs,
                masked_ss,
                cs_otp,
                ss_otp,
            } => {
                let mut masked_cs = vm.decode(*masked_cs).map_err(FError::vm)?;
                let Some(masked_cs) = masked_cs.try_recv().map_err(FError::vm)? else {
                    return Ok(());
                };
                let mut masked_ss = vm.decode(*masked_ss).map_err(FError::vm)?;
                let Some(masked_ss) = masked_ss.try_recv().map_err(FError::vm)? else {
                    return Ok(());
                };

                let (ckey, civ, skey, siv) = if self.role == Role::Leader {
                    let cs_otp = cs_otp.expect("leader knows cs otp");
                    let ss_otp = ss_otp.expect("leader knows ss otp");

                    let mut cs = masked_cs;
                    let mut ss = masked_ss;

                    cs.iter_mut().zip(cs_otp).for_each(|(cs, otp)| {
                        *cs ^= otp;
                    });

                    ss.iter_mut().zip(ss_otp).for_each(|(ss, otp)| {
                        *ss ^= otp;
                    });
                    let ckey: [u8; 16] = hkdf_expand_label(&cs, b"key", &[], 16)
                        .try_into()
                        .expect("output is 16 bytes");
                    let civ: [u8; 12] = hkdf_expand_label(&cs, b"iv", &[], 12)
                        .try_into()
                        .expect("output is 12 bytes");
                    let skey: [u8; 16] = hkdf_expand_label(&ss, b"key", &[], 16)
                        .try_into()
                        .expect("output is 16 bytes");
                    let siv: [u8; 12] = hkdf_expand_label(&ss, b"iv", &[], 12)
                        .try_into()
                        .expect("output is 12 bytes");

                    (Some(ckey), Some(civ), Some(skey), Some(siv))
                } else {
                    (None, None, None, None)
                };

                self.state = State::KeysDecoded {
                    ckey,
                    civ,
                    skey,
                    siv,
                }
            }
            State::MasterSecret(ms) => {
                ms.flush(vm)?;

                if ms.is_complete() {
                    self.state = State::WantsHandshakeHash;
                }
            }
            State::Application(app) => {
                app.flush(vm)?;

                if app.is_complete() {
                    self.state = State::Complete(app.keys()?);
                }
            }
            _ => (),
        }

        Ok(())
    }

    /// Sets the hash of the ClientHello message.
    pub fn set_hello_hash(&mut self, hello_hash: [u8; 32]) -> Result<(), FError> {
        match &mut self.state {
            State::Handshake { secrets, .. } => {
                secrets.set_hello_hash(hello_hash)?;
                Ok(())
            }
            _ => Err(FError::state("not in Handshake state")),
        }
    }

    /// Returns handshake keys.
    pub fn handshake_keys(&mut self) -> Result<HandshakeKeys, FError> {
        if self.role != Role::Leader {
            return Err(FError::state("only leader can access handshake keys"));
        }
        match self.state {
            State::KeysDecoded {
                ckey,
                civ,
                skey,
                siv,
            } => Ok(HandshakeKeys {
                client_write_key: ckey.expect("leader knows key"),
                client_iv: civ.expect("leader knows key"),
                server_write_key: skey.expect("leader knows key"),
                server_iv: siv.expect("leader knows key"),
            }),
            _ => Err(FError::state("not in HandshakeComplete state")),
        }
    }

    /// Continues the key schedule to derive application keys.
    ///
    /// Used after the handshake keys are computed and before the handshake
    /// hash is set.
    pub fn continue_to_app_keys(&mut self) -> Result<(), FError> {
        match self.state {
            State::KeysDecoded { .. } => {
                let ms = mem::take(&mut self.master_secret).expect("master secret is set");
                self.state = State::MasterSecret(ms);
                Ok(())
            }
            _ => Err(FError::state("not in KeysDecoded state")),
        }
    }

    /// Sets the handshake hash.
    pub fn set_handshake_hash(&mut self, handshake_hash: [u8; 32]) -> Result<(), FError> {
        match &mut self.state {
            State::WantsHandshakeHash => {
                let mut app =
                    mem::take(&mut self.application).expect("application secrets are set");
                app.set_handshake_hash(handshake_hash)?;
                self.state = State::Application(app);
                Ok(())
            }
            _ => Err(FError::state("not in WantsHandshakeHash state")),
        }
    }

    /// Returns VM references to the application keys.
    pub fn application_keys(&mut self) -> Result<ApplicationKeys, FError> {
        match self.state {
            State::Complete(keys) => Ok(keys),
            _ => Err(FError::state("not in Complete state")),
        }
    }
}

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub(crate) enum State {
    Initialized,
    /// The state in which some of the handshake secrets are computed in MPC.
    Handshake {
        secrets: HandshakeSecrets,
        masked_cs: Array<U8, 32>,
        masked_ss: Array<U8, 32>,
        cs_otp: Option<[u8; 32]>,
        ss_otp: Option<[u8; 32]>,
    },
    /// The state after all handshake-related MPC operations were completed
    /// and the keys need to be decoded.
    WantsDecodedKeys {
        masked_cs: Array<U8, 32>,
        masked_ss: Array<U8, 32>,
        cs_otp: Option<[u8; 32]>,
        ss_otp: Option<[u8; 32]>,
    },
    /// The state after the handshake keys were decoded and made known to the
    /// leader.
    KeysDecoded {
        ckey: Option<[u8; 16]>,
        civ: Option<[u8; 12]>,
        skey: Option<[u8; 16]>,
        siv: Option<[u8; 12]>,
    },
    /// The state in which the master secret is computed.
    ///
    /// Computing master secret before handshake hash is set can potentially
    /// improve overall performance.
    MasterSecret(HkdfExtract),
    /// The state in which the master secret has been computed and the
    /// handshake hash is expected to be set.
    WantsHandshakeHash,
    /// The state in which the application secrets are derived.
    Application(ApplicationSecrets),
    Complete(ApplicationKeys),
    Error,
}

impl State {
    pub(crate) fn take(&mut self) -> State {
        std::mem::replace(self, State::Error)
    }
}

/// Handshake keys computed by the key schedule.
#[derive(Debug, Clone, Copy)]
pub struct HandshakeKeys {
    /// Client write key.
    pub client_write_key: [u8; 16],
    /// Server write key.
    pub server_write_key: [u8; 16],
    /// Client IV.
    pub client_iv: [u8; 12],
    /// Server IV.
    pub server_iv: [u8; 12],
}

/// Application keys computed by the key schedule.
#[derive(Debug, Clone, Copy)]
pub struct ApplicationKeys {
    /// Client write key.
    pub client_write_key: Array<U8, 16>,
    /// Server write key.
    pub server_write_key: Array<U8, 16>,
    /// Client IV.
    pub client_iv: Array<U8, 12>,
    /// Server IV.
    pub server_iv: Array<U8, 12>,
}

#[cfg(test)]
mod tests {
    use crate::{
        test_utils::mock_vm,
        tls13::{Role, Tls13KeySched},
        ApplicationKeys, HandshakeKeys, Mode,
    };
    use mpz_common::{context::test_st_context, Context};
    use mpz_vm_core::{
        memory::{
            binary::{Binary, U8},
            Array, MemoryExt, ViewExt,
        },
        Vm,
    };
    use rstest::*;

    #[rstest]
    #[case::normal(Mode::Normal)]
    #[case::reduced(Mode::Reduced)]
    #[tokio::test]
    async fn test_tls13_key_sched(#[case] mode: Mode) {
        let (
            pms,
            hello_hash,
            handshake_hash,
            ckey_hs,
            civ_hs,
            skey_hs,
            siv_hs,
            ckey_app,
            civ_app,
            skey_app,
            siv_app,
        ) = test_fixtures();

        let (mut ctx_a, mut ctx_b) = test_st_context(8);
        let (mut leader, mut follower) = mock_vm();

        // PMS is a private output from previous MPC computations not known
        // to either party. For simplicity, it is marked public in this test.
        let pms: [u8; 32] = pms.try_into().unwrap();

        fn setup_ks(
            vm: &mut (dyn Vm<Binary> + Send),
            pms: [u8; 32],
            mode: Mode,
            role: Role,
        ) -> Tls13KeySched {
            let secret: Array<U8, 32> = vm.alloc().unwrap();
            vm.mark_public(secret).unwrap();
            vm.assign(secret, pms).unwrap();
            vm.commit(secret).unwrap();

            let mut ks = Tls13KeySched::new(mode, role);
            ks.alloc(vm, secret).unwrap();
            ks
        }

        let mut leader_ks = setup_ks(&mut leader, pms, mode, Role::Leader);
        let mut follower_ks = setup_ks(&mut follower, pms, mode, Role::Follower);

        async fn run_ks(
            vm: &mut (dyn Vm<Binary> + Send),
            ks: &mut Tls13KeySched,
            ctx: &mut Context,
            role: Role,
            mode: Mode,
            hello_hash: Vec<u8>,
            handshake_hash: Vec<u8>,
        ) -> Result<
            (
                Option<HandshakeKeys>,
                ([u8; 16], [u8; 12], [u8; 16], [u8; 12]),
            ),
            Box<dyn std::error::Error>,
        > {
            let res = async move {
                vm.execute_all(ctx).await.unwrap();

                flush_execute(ks, vm, ctx, false).await;

                ks.set_hello_hash(hello_hash.try_into().unwrap()).unwrap();

                // One extra flush to process decoded handshake secrets.
                flush_execute(ks, vm, ctx, true).await;

                let hs_keys = if role == Role::Leader {
                    Some(ks.handshake_keys().unwrap())
                } else {
                    None
                };

                ks.continue_to_app_keys().unwrap();

                flush_execute(ks, vm, ctx, false).await;

                ks.set_handshake_hash(handshake_hash.try_into().unwrap())
                    .unwrap();

                if mode == Mode::Reduced {
                    // One extra flush to process decoded inner_partial.
                    flush_execute(ks, vm, ctx, true).await;
                } else {
                    flush_execute(ks, vm, ctx, false).await;
                }

                let ApplicationKeys {
                    client_write_key,
                    client_iv,
                    server_write_key,
                    server_iv,
                } = ks.application_keys().unwrap();
                let mut ckey_fut = vm.decode(client_write_key).unwrap();
                let mut civ_fut = vm.decode(client_iv).unwrap();
                let mut skey_fut = vm.decode(server_write_key).unwrap();
                let mut siv_fut = vm.decode(server_iv).unwrap();
                vm.execute_all(ctx).await.unwrap();
                let ckey = ckey_fut.try_recv().unwrap().unwrap();
                let civ = civ_fut.try_recv().unwrap().unwrap();
                let skey = skey_fut.try_recv().unwrap().unwrap();
                let siv = siv_fut.try_recv().unwrap().unwrap();

                (hs_keys, (ckey, civ, skey, siv))
            }
            .await;

            Ok(res)
        }

        let (out_leader, out_follower) = tokio::try_join!(
            run_ks(
                &mut leader,
                &mut leader_ks,
                &mut ctx_a,
                Role::Leader,
                mode,
                hello_hash.clone(),
                handshake_hash.clone()
            ),
            run_ks(
                &mut follower,
                &mut follower_ks,
                &mut ctx_b,
                Role::Follower,
                mode,
                hello_hash,
                handshake_hash
            )
        )
        .unwrap();

        let hs_keys_leader = out_leader.0.unwrap();

        assert_eq!(
            (
                hs_keys_leader.client_write_key.to_vec(),
                hs_keys_leader.client_iv.to_vec(),
                hs_keys_leader.server_write_key.to_vec(),
                hs_keys_leader.server_iv.to_vec()
            ),
            (ckey_hs, civ_hs, skey_hs, siv_hs)
        );

        let app_keys_leader = out_leader.1;
        let app_keys_follower = out_follower.1;
        assert_eq!(app_keys_leader, app_keys_follower);

        assert_eq!(
            app_keys_leader,
            (
                ckey_app.try_into().unwrap(),
                civ_app.try_into().unwrap(),
                skey_app.try_into().unwrap(),
                siv_app.try_into().unwrap()
            )
        );
    }

    async fn flush_execute(
        ks: &mut Tls13KeySched,
        vm: &mut (dyn Vm<Binary> + Send),
        ctx: &mut Context,
        // Whether after executing the VM, one extra flush is required.
        extra_flush: bool,
    ) {
        assert!(ks.wants_flush());
        ks.flush(vm).unwrap();
        vm.execute_all(ctx).await.unwrap();
        if extra_flush {
            assert!(ks.wants_flush());
            ks.flush(vm).unwrap();
        }
        assert!(!ks.wants_flush())
    }

    // Reference values from https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors-06
    #[allow(clippy::type_complexity)]
    fn test_fixtures() -> (
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
        Vec<u8>,
    ) {
        (
            // PMS
            from_hex_str("81 51 d1 46 4c 1b 55 53 36 23 b9 c2 24 6a 6a 0e 6e 7e 18 50 63 e1 4a fd af f0 b6 e1 c6 1a 86 42"),
            // HELLO_HASH
            from_hex_str("c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d"),
            // HANDSHAKE_HASH
            from_hex_str("f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf"),
            // CKEY_HS
            from_hex_str("26 79 a4 3e 1d 76 78 40 34 ea 17 97 d5 ad 26 49"),
            // CIV_HS
            from_hex_str("54 82 40 52 90 dd 0d 2f 81 c0 d9 42"),
            // SKEY_HS
            from_hex_str("c6 6c b1 ae c5 19 df 44 c9 1e 10 99 55 11 ac 8b"),
            // SIV_HS
            from_hex_str("f7 f6 88 4c 49 81 71 6c 2d 0d 29 a4"),
            // CKEY_APP
            from_hex_str("88 b9 6a d6 86 c8 4b e5 5a ce 18 a5 9c ce 5c 87"),
            // CIV_APP
            from_hex_str("b9 9d c5 8c d5 ff 5a b0 82 fd ad 19"),
            // SKEY_APP
            from_hex_str("a6 88 eb b5 ac 82 6d 6f 42 d4 5c 0c c4 4b 9b 7d"),
            // SIV_APP
            from_hex_str("c1 ca d4 42 5a 43 8b 5d e7 14 83 0a"),
        )
    }

    fn from_hex_str(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }
}
