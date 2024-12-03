use std::{
    fs::{create_dir_all, File},
    io::Write,
    path::Path,
};

use ff::Field;
use halo2_poseidon::poseidon::primitives::{generate_constants, Mds, Spec};
use halo2_proofs::halo2curves::bn256::Fr as F;
use rayon::prelude::*;

// Specs for Poseidon permutations based on:
// [ref1] - https://github.com/iden3/circomlib/blob/0a045aec50d51396fcd86a568981a5a0afb99e95/circuits/poseidon.circom

/// The number of partial rounds for each supported rate.
///
/// The first element in the array corresponds to rate 1.
/// (`N_ROUNDS_P` in ref1).
const N_ROUNDS_P: [usize; 16] = [
    56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68,
];

/// The number of full rounds.
///
/// (`nRoundsF` in ref1).
const FULL_ROUNDS: usize = 8;

/// The first correct and secure MDS index for the given spec.
///
/// This value can be audited by printing the number of iterations in the MDS
/// generation function at: https://github.com/daira/pasta-hadeshash/blob/5959f2684a25b372fba347e62467efb00e7e2c3f/code/generate_parameters_grain.sage#L113
///
/// E.g. for Spec16, run the script with
/// `sage generate_parameters_grain.sage 1 0 254 17 8 68
/// 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`
const FIRST_SECURE_MDS_INDEX: usize = 0;

#[derive(Debug, Clone, Copy)]
pub struct CircomlibSpec<const WIDTH: usize, const RATE: usize>;

impl<const WIDTH: usize, const RATE: usize> Spec<F, WIDTH, RATE> for CircomlibSpec<WIDTH, RATE> {
    fn full_rounds() -> usize {
        FULL_ROUNDS
    }

    fn partial_rounds() -> usize {
        N_ROUNDS_P[RATE - 1]
    }

    fn sbox(val: F) -> F {
        val.pow_vartime([5])
    }

    fn secure_mds() -> usize {
        FIRST_SECURE_MDS_INDEX
    }

    fn constants() -> (Vec<[F; WIDTH]>, Mds<F, WIDTH>, Mds<F, WIDTH>) {
        generate_constants::<_, Self, WIDTH, RATE>()
    }
}

// Generates constants for the given rate and stores them.
macro_rules! generate {
    ($rate:expr) => {{
        const RATE: usize = $rate;
        const WIDTH: usize = RATE + 1;

        let (round_const, mds, mds_inv) = CircomlibSpec::<WIDTH, RATE>::constants();

        let dest_path = Path::new("src/generated").join(format!("rate{:?}_constants.rs", RATE));

        let mut f = File::create(&dest_path)?;

        writeln!(f, "use halo2_proofs::halo2curves::bn256::Fr as F;")?;
        writeln!(f)?;

        writeln!(
            f,
            "pub const ROUND_CONSTANTS: [[F; {:?}]; {:?}] = [",
            WIDTH,
            round_const.len()
        )?;
        for array in round_const {
            writeln!(f, "[")?;
            for field in array {
                writeln!(f, "F::from_raw({}),", to_raw(field))?;
            }
            writeln!(f, "],")?;
        }
        writeln!(f, "];")?;
        writeln!(f)?;

        writeln!(f, "pub const MDS: [[F; {:?}]; {:?}] = [", WIDTH, WIDTH)?;
        for array in mds {
            writeln!(f, "[")?;
            for field in array {
                writeln!(f, "F::from_raw({}),", to_raw(field))?;
            }
            writeln!(f, "],")?;
        }
        writeln!(f, "];")?;
        writeln!(f)?;

        writeln!(f, "pub const MDS_INV: [[F; {:?}]; {:?}] = [", WIDTH, WIDTH)?;
        for array in mds_inv {
            writeln!(f, "[")?;
            for field in array {
                writeln!(f, "F::from_raw({}),", to_raw(field))?;
            }
            writeln!(f, "],")?;
        }
        writeln!(f, "];")?;
        writeln!(f)?;

        Ok(())
    }};
}

fn main() -> anyhow::Result<()> {
    let dest_dir = Path::new("src/generated");
    create_dir_all(dest_dir).expect("Could not create generated directory");

    let tasks = vec![
        || -> anyhow::Result<()> { generate!(1) },
        || -> anyhow::Result<()> { generate!(2) },
        || -> anyhow::Result<()> { generate!(3) },
        || -> anyhow::Result<()> { generate!(4) },
        || -> anyhow::Result<()> { generate!(5) },
        || -> anyhow::Result<()> { generate!(6) },
        || -> anyhow::Result<()> { generate!(7) },
        || -> anyhow::Result<()> { generate!(8) },
        || -> anyhow::Result<()> { generate!(9) },
        || -> anyhow::Result<()> { generate!(10) },
        || -> anyhow::Result<()> { generate!(11) },
        || -> anyhow::Result<()> { generate!(12) },
        || -> anyhow::Result<()> { generate!(13) },
        || -> anyhow::Result<()> { generate!(14) },
        || -> anyhow::Result<()> { generate!(15) },
        || -> anyhow::Result<()> { generate!(16) },
    ];

    tasks.par_iter().for_each(|task| task().unwrap());

    Ok(())
}

// Converts `F` into a stringified form which can be passed to `F::from_raw()`.
fn to_raw(f: F) -> String {
    let limbs_le: [String; 4] = f
        .to_bytes()
        .chunks_exact(8)
        .map(|limb| {
            // This hex number will be converted to u64. Rust expects it to be big-endian.
            format!(
                "0x{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                limb[7], limb[6], limb[5], limb[4], limb[3], limb[2], limb[1], limb[0]
            )
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("should be 4 chunks");

    format!(
        "[{}, {}, {}, {}]",
        limbs_le[0], limbs_le[1], limbs_le[2], limbs_le[3]
    )
}
