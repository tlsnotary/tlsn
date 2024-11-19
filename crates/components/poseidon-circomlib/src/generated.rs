use ff::Field;
use halo2_poseidon::poseidon::primitives::Mds;
use halo2_proofs::halo2curves::bn256::Fr as F;

mod rate10_constants;
mod rate11_constants;
mod rate12_constants;
mod rate13_constants;
mod rate14_constants;
mod rate15_constants;
mod rate16_constants;
mod rate1_constants;
mod rate2_constants;
mod rate3_constants;
mod rate4_constants;
mod rate5_constants;
mod rate6_constants;
mod rate7_constants;
mod rate8_constants;
mod rate9_constants;

pub fn provide_constants<const WIDTH: usize>() -> (Vec<[F; WIDTH]>, Mds<F, WIDTH>, Mds<F, WIDTH>) {
    let mut rc: Vec<[F; WIDTH]> = Vec::new();
    let mut mds = [[F::ZERO; WIDTH]; WIDTH];
    let mut mds_inv = [[F::ZERO; WIDTH]; WIDTH];

    let mut buffer = [F::ZERO; WIDTH];

    // Copies source constants into generic-sized arrays.
    macro_rules! from_constants {
        ($source:ident) => {{
            for array in $source::ROUND_CONSTANTS {
                buffer.copy_from_slice(&array);
                rc.push(buffer);
            }
            for (idx, array) in $source::MDS.iter().enumerate() {
                buffer.copy_from_slice(array);
                mds[idx] = buffer;
            }
            for (idx, array) in $source::MDS_INV.iter().enumerate() {
                buffer.copy_from_slice(array);
                mds_inv[idx] = buffer;
            }
        }};
    }

    // Poseidon's state width equals its rate + 1.
    let rate = WIDTH - 1;
    match rate {
        1 => {
            from_constants!(rate1_constants);
        }
        2 => {
            from_constants!(rate2_constants);
        }
        3 => {
            from_constants!(rate3_constants);
        }
        4 => {
            from_constants!(rate4_constants);
        }
        5 => {
            from_constants!(rate5_constants);
        }
        6 => {
            from_constants!(rate6_constants);
        }
        7 => {
            from_constants!(rate7_constants);
        }
        8 => {
            from_constants!(rate8_constants);
        }
        9 => {
            from_constants!(rate9_constants);
        }
        10 => {
            from_constants!(rate10_constants);
        }
        11 => {
            from_constants!(rate11_constants);
        }
        12 => {
            from_constants!(rate12_constants);
        }
        13 => {
            from_constants!(rate13_constants);
        }
        14 => {
            from_constants!(rate14_constants);
        }
        15 => {
            from_constants!(rate15_constants);
        }
        16 => {
            from_constants!(rate16_constants);
        }
        _ => unimplemented!("rate higher than 16 is not supported"),
    }

    (rc, mds, mds_inv)
}
