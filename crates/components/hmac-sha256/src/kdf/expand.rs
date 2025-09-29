//! `HKDF-Expand-Label` function as defined in TLS 1.3.

use mpz_vm_core::{
    memory::{
        binary::{Binary, U8},
        Vector,
    },
    Vm,
};

use crate::{
    hmac::{clear, Hmac},
    kdf::expand::label::make_hkdf_label,
    FError, Mode,
};

pub(crate) mod label;
pub(crate) mod normal;
pub(crate) mod reduced;

/// A zero_length HKDF-Expand-Label context.
pub(crate) const EMPTY_CTX: [u8; 0] = [];

/// Functionality for computing `HKDF-Expand-Label` with a private secret
/// and public label and context.
#[derive(Debug)]
pub(crate) enum HkdfExpand {
    Reduced(reduced::HkdfExpand),
    Normal(normal::HkdfExpand),
}

impl HkdfExpand {
    /// Allocates a new HKDF-Expand-Label with the `hmac`
    /// instantiated with the secret.
    pub(crate) fn alloc(
        mode: Mode,
        vm: &mut dyn Vm<Binary>,
        // Partial hash states of the secret.
        hmac: Hmac,
        // Human-readable label.
        label: &'static [u8],
        // Context.
        ctx: Option<&[u8]>,
        // Context length.
        ctx_len: usize,
        // Output length.
        out_len: usize,
    ) -> Result<Self, FError> {
        let prf = match mode {
            Mode::Reduced => {
                if let Hmac::Reduced(hmac) = hmac {
                    let mut hkdf = reduced::HkdfExpand::alloc(hmac, label, out_len)?;
                    if let Some(ctx) = ctx {
                        hkdf.set_ctx(ctx)?;
                    }
                    Self::Reduced(hkdf)
                } else {
                    unreachable!("modes always match");
                }
            }
            Mode::Normal => {
                if let Hmac::Normal(hmac) = hmac {
                    let mut hkdf = normal::HkdfExpand::alloc(vm, hmac, label, ctx_len, out_len)?;
                    if let Some(ctx) = ctx {
                        hkdf.set_ctx(ctx)?;
                    }
                    Self::Normal(hkdf)
                } else {
                    unreachable!("modes always match");
                }
            }
        };
        Ok(prf)
    }

    /// Whether this functionality needs to be flushed.
    pub(crate) fn wants_flush(&self) -> bool {
        match self {
            HkdfExpand::Reduced(hkdf) => hkdf.wants_flush(),
            HkdfExpand::Normal(hkdf) => hkdf.wants_flush(),
        }
    }

    /// Flushes the functionality.
    pub(crate) fn flush(&mut self, vm: &mut dyn Vm<Binary>) -> Result<(), FError> {
        match self {
            HkdfExpand::Reduced(hkdf) => hkdf.flush(vm),
            HkdfExpand::Normal(hkdf) => hkdf.flush(vm),
        }
    }

    /// Sets the HKDF-Expand-Label context.
    pub(crate) fn set_ctx(&mut self, ctx: &[u8]) -> Result<(), FError> {
        match self {
            HkdfExpand::Reduced(hkdf) => hkdf.set_ctx(ctx),
            HkdfExpand::Normal(hkdf) => hkdf.set_ctx(ctx),
        }
    }

    /// Whether the context has been set.
    pub(crate) fn is_ctx_set(&self) -> bool {
        match self {
            HkdfExpand::Reduced(hkdf) => hkdf.is_ctx_set(),
            HkdfExpand::Normal(hkdf) => hkdf.is_ctx_set(),
        }
    }

    /// Returns the HKDF-Expand-Label output.
    pub(crate) fn output(&self) -> Vector<U8> {
        match self {
            HkdfExpand::Reduced(hkdf) => hkdf.output(),
            HkdfExpand::Normal(hkdf) => hkdf.output(),
        }
    }

    /// Whether this functionality is complete.
    pub(crate) fn is_complete(&self) -> bool {
        match self {
            HkdfExpand::Reduced(hkdf) => hkdf.is_complete(),
            HkdfExpand::Normal(hkdf) => hkdf.is_complete(),
        }
    }
}

/// Computes `HKDF-Expand-Label` as defined in TLS 1.3.
pub(crate) fn hkdf_expand_label(key: &[u8], label: &[u8], ctx: &[u8], len: usize) -> Vec<u8> {
    hkdf_expand(key, &make_hkdf_label(label, ctx, len), len)
}

/// Computes `HKDF-Expand` as defined in https://datatracker.ietf.org/doc/html/rfc5869
fn hkdf_expand(prk: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    assert!(len <= 32, "output length larger than 32 is not supported");
    let mut info = info.to_vec();
    info.push(0x01);
    clear::hmac_sha256(prk, &info)[..len].to_vec()
}

#[cfg(test)]
mod tests {
    use crate::{
        hmac::{normal::HmacNormal, Hmac},
        kdf::expand::{hkdf_expand_label, HkdfExpand},
        test_utils::mock_vm,
        Mode,
    };
    use mpz_common::context::test_st_context;
    use mpz_vm_core::{
        memory::{binary::Binary, MemoryExt, ViewExt},
        Execute, Vm,
    };
    use rstest::*;

    #[rstest]
    #[case::normal(Mode::Normal)]
    #[case::reduced(Mode::Reduced)]
    #[tokio::test]
    async fn test_hkdf_expand(#[case] mode: Mode) {
        for fixture in test_fixtures() {
            let (label, prk, ctx, output) = fixture;

            let (mut ctx_a, mut ctx_b) = test_st_context(8);
            let (mut leader, mut follower) = mock_vm();

            fn setup_hkdf(
                vm: &mut (dyn Vm<Binary> + Send),
                prk: [u8; 32],
                label: &'static [u8],
                ctx: Option<&[u8]>,
                ctx_len: usize,
                out_len: usize,
                mode: Mode,
            ) -> HkdfExpand {
                let secret = vm.alloc_vec(32).unwrap();
                vm.mark_public(secret).unwrap();
                vm.assign(secret, prk.to_vec()).unwrap();
                vm.commit(secret).unwrap();

                let hmac = if mode == Mode::Normal {
                    Hmac::Normal(HmacNormal::alloc(vm, secret).unwrap())
                } else {
                    use crate::hmac::reduced::HmacReduced;

                    Hmac::Reduced(HmacReduced::alloc(vm, secret).unwrap())
                };

                HkdfExpand::alloc(mode, vm, hmac, label, ctx, ctx_len, out_len).unwrap()
            }

            let mut hkdf_leader = setup_hkdf(
                &mut leader,
                prk.clone().try_into().unwrap(),
                label,
                Some(&ctx),
                ctx.len(),
                output.len(),
                mode,
            );

            let mut hkdf_follower = setup_hkdf(
                &mut follower,
                prk.clone().try_into().unwrap(),
                label,
                Some(&ctx),
                ctx.len(),
                output.len(),
                mode,
            );

            let out_leader = hkdf_leader.output();
            let mut leader_decode_fut = leader.decode(out_leader).unwrap();

            let out_follower = hkdf_follower.output();
            let mut follower_decode_fut = follower.decode(out_follower).unwrap();

            tokio::try_join!(
                async {
                    leader.execute_all(&mut ctx_a).await.unwrap();
                    assert!(hkdf_leader.wants_flush());
                    hkdf_leader.flush(&mut leader).unwrap();
                    assert!(!hkdf_leader.wants_flush());
                    leader.execute_all(&mut ctx_a).await.unwrap();

                    Ok::<(), Box<dyn std::error::Error>>(())
                },
                async {
                    follower.execute_all(&mut ctx_b).await.unwrap();
                    assert!(hkdf_follower.wants_flush());
                    hkdf_follower.flush(&mut follower).unwrap();
                    assert!(!hkdf_follower.wants_flush());
                    follower.execute_all(&mut ctx_b).await.unwrap();

                    Ok::<(), Box<dyn std::error::Error>>(())
                }
            )
            .unwrap();

            let out_leader = leader_decode_fut.try_recv().unwrap().unwrap();
            let out_follower = follower_decode_fut.try_recv().unwrap().unwrap();
            assert_eq!(out_leader, out_follower);
            assert_eq!(out_leader, output);
        }
    }

    #[test]
    fn test_hkdf_expand_label() {
        for fixture in test_fixtures() {
            let (label, prk, ctx, output) = fixture;
            let out = hkdf_expand_label(&prk, label, &ctx, output.len());
            assert_eq!(out, output);
        }
    }

    // Reference values from https://datatracker.ietf.org/doc/html/draft-ietf-tls-tls13-vectors-06
    #[allow(clippy::type_complexity)]
    fn test_fixtures() -> Vec<(&'static [u8], Vec<u8>, Vec<u8>, Vec<u8>)> {
        vec![(
            // LABEL
            b"c hs traffic",
            // PRK
            from_hex_str("5b 4f 96 5d f0 3c 68 2c 46 e6 ee 86 c3 11 63 66 15 a1 d2 bb b2 43 45 c2 52 05 95 3c 87 9e 8d 06").to_vec(),
            // CTX
            from_hex_str("c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d").to_vec(),
            // OUTPUT
            from_hex_str("e2 e2 32 07 bd 93 fb 7f e4 fc 2e 29 7a fe ab 16 0e 52 2b 5a b7 5d 64 a8 6e 75 bc ac 3f 3e 51 03").to_vec(),
        ),
        (
            // LABEL
            b"s hs traffic",
            // PRK
            from_hex_str("5b 4f 96 5d f0 3c 68 2c 46 e6 ee 86 c3 11 63 66 15 a1 d2 bb b2 43 45 c2 52 05 95 3c 87 9e 8d 06").to_vec(),
            // CTX
            from_hex_str("c6 c9 18 ad 2f 41 99 d5 59 8e af 01 16 cb 7a 5c 2c 14 cb 54 78 12 18 88 8d b7 03 0d d5 0d 5e 6d").to_vec(),
            // OUTPUT
            from_hex_str("3b 7a 83 9c 23 9e f2 bf 0b 73 05 a0 e0 c4 e5 a8 c6 c6 93 30 a7 53 b3 08 f5 e3 a8 3a a2 ef 69 79").to_vec(),
        ),
        (
            // LABEL
            b"c ap traffic",
            // PRK
            from_hex_str("5c 79 d1 69 42 4e 26 2b 56 32 03 62 7b e4 eb 51 03 3f 58 8c 43 c9 ce 03 73 37 2d bc bc 01 85 a7").to_vec(),
            // CTX
            from_hex_str("f8 c1 9e 8c 77 c0 38 79 bb c8 eb 6d 56 e0 0d d5 d8 6e f5 59 27 ee fc 08 e1 b0 02 b6 ec e0 5d bf").to_vec(),
            // OUTPUT
            from_hex_str("e2 f0 db 6a 82 e8 82 80 fc 26 f7 3c 89 85 4e e8 61 5e 25 df 28 b2 20 79 62 fa 78 22 26 b2 36 26").to_vec(),
        )
        ]
    }

    fn from_hex_str(s: &str) -> Vec<u8> {
        hex::decode(s.split_whitespace().collect::<String>()).unwrap()
    }
}
