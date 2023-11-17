use halo2_gadgets::poseidon::{primitives::ConstantLength, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr as F,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};

use super::{
    poseidon::{
        circuit_config::{configure_poseidon_rate_1, configure_poseidon_rate_15},
        spec::{Spec1, Spec15},
    },
    utils::{bigint_to_256bits, bigint_to_f, bits_to_limbs, f_to_bigint},
};

use num::BigUint;
use std::convert::TryInto;

// See circuit_diagram.pdf for a diagram of the circuit

// The AuthDecode protocol decodes a chunk of X bits at a time.
// Each of the bit requires 1 corresponding public input - a delta.
// We want the deltas to use up as few instance columns as possible
// because more instance columns means more prover time. We also want
// K to stay as low as possible since low K also improves prover time.
// The best ratio is achieved with K==6 and 68 instance columns.

// However, 68-bit limbs are awkward to work with. So we choose to have
// 64 columns and 4 rows, to place all the field element's bits into.

// Our circuit's K is 6, which gives us 2^6-6=58 useful rows
// (halo2 reserves 6 rows for internal purposes).
// It requires 4 64-cell rows in order to hold all the bits of one field element.

// The total amount of field elements we can decode is 58/4 = 14 1/2,
// which equals to 14 253-bit field elements plus 1 field element of 128 bits.
// The remaining 125 bits of the 15th element will be used for the salt.

// We could have much simpler logic if we just used 253 instance columns.
// But compared to 64 columns, that would increase the prover time 2x.

/// The total amount of field elements that will be decoded and hashed.
pub const TOTAL_FIELD_ELEMENTS: usize = 15;

/// The amount of "full" field elements. We fully pack the plaintext bits
/// into these field elements.
/// The last field element is not "full" since it contains only two 64-bit
/// limbs of plaintext.
pub const FULL_FIELD_ELEMENTS: usize = 14;

/// The parameter informing halo2 about the upper bound of how many rows our
/// circuit uses. This is a power of 2.
pub const K: u32 = 6;

/// For one row of the circuit, this is the amount of advice cells to put
/// plaintext bits into and also this is the amount of instance cells to
/// put deltas into.  
pub const CELLS_PER_ROW: usize = 64;

/// The amount of rows that can be used by the circuit.
///
/// When K == 6, halo2 reserves 6 rows internally, so the actual amount of rows
/// that the circuit can use is 2^K - 6 = 58.
/// If we ever change K, we should re-compute the number of reserved rows with
/// (cs.blinding_factors() + 1)
pub const USEFUL_ROWS: usize = 58;

/// The size of the salt of the hash in bits.
///
/// We don't use the usual 128 bits, because it is convenient to put two 64-bit
/// limbs of plaintext into the field element (which has 253 useful bits, see
/// [super::USEFUL_BITS]) and use the remaining 125 bits of the field element
/// for the salt (see [crate::Salt]).
pub const SALT_SIZE: usize = 125;

#[derive(Clone, Debug)]
pub struct TopLevelConfig {
    /// Each plaintext field element is decomposed into 256 bits
    /// and each 64-bit limb is places on a row
    bits: [Column<Advice>; CELLS_PER_ROW],
    /// Space to calculate intermediate sums
    scratch_space: [Column<Advice>; 5],
    /// Expected dot product for each 64-bit limb
    dot_product: Column<Advice>,
    /// Expected 64-bit limb composed into an integer
    expected_limbs: Column<Advice>,
    /// The salt will be placed into the 1st row of this column
    salt: Column<Advice>,

    /// Each row of deltas corresponds to one limb of plaintext
    deltas: [Column<Instance>; CELLS_PER_ROW],

    /// Since halo2 does not allow to constrain public inputs in instance columns
    /// directly, we first need to copy the inputs into this advice column
    advice_from_instance: Column<Advice>,

    // SELECTORS.
    // Below is the description of what happens when a selector
    // is activated for a given row:
    /// Computes a dot product
    selector_dot_product: Selector,
    /// Composes a given limb from bits into an integer.
    /// The highest limb corresponds to the selector with index 0.
    selector_compose: [Selector; 4],
    /// Checks binariness of decomposed bits
    selector_binary_check: Selector,
    /// Sums 4 cells
    selector_sum4: Selector,
    /// Sums 2 cells
    selector_sum2: Selector,
    /// Left-shifts the first cell by the size of the salt and adds the salt
    selector_add_salt: Selector,

    /// config for Poseidon with rate 15
    poseidon_config_rate15: Pow5Config<F, 16, 15>,
    /// config for Poseidon with rate 1
    poseidon_config_rate1: Pow5Config<F, 2, 1>,

    /// Contains 3 public input in this order:
    /// [plaintext hash, label sum hash, zero sum].
    /// Does **NOT** contain deltas.
    public_inputs: Column<Instance>,
}

pub struct AuthDecodeCircuit {
    /// plaintext is private input
    plaintext: [F; TOTAL_FIELD_ELEMENTS],
    /// salt is private input
    salt: F,
    /// deltas is a public input.
    /// Since halo2 doesn't allow to access deltas which we passed in
    /// [crate::prover::Prove::prove],
    /// we pass it here again to be able to compute the in-circuit expected values.
    /// To make handling simpler, this is a matrix of rows, where each row corresponds
    /// to a 64-bit limb of the plaintext.
    deltas: [[F; CELLS_PER_ROW]; USEFUL_ROWS],
}

impl Circuit<F> for AuthDecodeCircuit {
    type Config = TopLevelConfig;
    type FloorPlanner = SimpleFloorPlanner;

    // halo2 requires this function
    fn without_witnesses(&self) -> Self {
        Self {
            plaintext: Default::default(),
            salt: Default::default(),
            deltas: [[Default::default(); CELLS_PER_ROW]; USEFUL_ROWS],
        }
    }

    /// Creates the circuit's columns, selectors and defines the gates.
    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // keep this in case we modify the circuit and change K but forget
        // to update USEFUL_ROWS
        // UPDATE: since we temporary changed [K] from 6 to 7, commenting out
        // this assert. Uncomment when
        // assert!(((1 << K) as usize) - (meta.blinding_factors() + 1) == USEFUL_ROWS);

        // ADVICE COLUMNS

        let bits: [Column<Advice>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
            .map(|_| meta.advice_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let dot_product = meta.advice_column();
        meta.enable_equality(dot_product);

        let expected_limbs = meta.advice_column();
        meta.enable_equality(expected_limbs);

        let salt = meta.advice_column();
        meta.enable_equality(salt);

        let scratch_space: [Column<Advice>; 5] = (0..5)
            .map(|_| {
                let c = meta.advice_column();
                meta.enable_equality(c);
                c
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let advice_from_instance = meta.advice_column();
        meta.enable_equality(advice_from_instance);

        // INSTANCE COLUMNS

        let deltas: [Column<Instance>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
            .map(|_| meta.instance_column())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let public_inputs = meta.instance_column();
        meta.enable_equality(public_inputs);

        // SELECTORS

        let selector_dot_product = meta.selector();
        let selector_binary_check = meta.selector();
        let selector_compose: [Selector; 4] = (0..4)
            .map(|_| meta.selector())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let selector_sum4 = meta.selector();
        let selector_sum2 = meta.selector();
        let selector_add_salt = meta.selector();

        // POSEIDON

        let poseidon_config_rate15 = configure_poseidon_rate_15::<Spec15>(15, meta);
        let poseidon_config_rate1 = configure_poseidon_rate_1::<Spec1>(1, meta);
        // we need to designate one column for global constants which the Poseidon
        // chip uses
        let global_constants = meta.fixed_column();
        meta.enable_constant(global_constants);

        // CONFIG

        // Put everything initialized above into a config
        let cfg = TopLevelConfig {
            bits,
            scratch_space,
            dot_product,
            expected_limbs,
            salt,
            advice_from_instance,

            deltas,

            selector_dot_product,
            selector_compose,
            selector_binary_check,
            selector_sum4,
            selector_sum2,
            selector_add_salt,

            poseidon_config_rate15,
            poseidon_config_rate1,

            public_inputs,
        };

        // MISC

        // build Expressions containing powers of 2, to be used in some gates
        let two = BigUint::from(2u8);
        let pow_2_x: Vec<_> = (0..256)
            .map(|i| Expression::Constant(bigint_to_f(&two.pow(i as u32))))
            .collect();

        // GATES

        // Computes the dot product of 2 sets of cells
        meta.create_gate("dot product", |meta| {
            let mut product = Expression::Constant(F::from(0));

            for i in 0..CELLS_PER_ROW {
                let delta = meta.query_instance(cfg.deltas[i], Rotation::cur());
                let bit = meta.query_advice(cfg.bits[i], Rotation::cur());
                product = product + delta * bit;
            }

            // constrain to match the expected value
            let expected = meta.query_advice(cfg.dot_product, Rotation::cur());
            let sel = meta.query_selector(cfg.selector_dot_product);
            vec![sel * (product - expected)]
        });

        // Batch-checks binariness of multiple bits
        meta.create_gate("binary check", |meta| {
            // create one Expression for each cell to be checked
            let expressions: [Expression<F>; CELLS_PER_ROW] = (0..CELLS_PER_ROW)
                .map(|i| {
                    let bit = meta.query_advice(cfg.bits[i], Rotation::cur());
                    bit.clone() * bit.clone() - bit
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let sel = meta.query_selector(cfg.selector_binary_check);

            // constrain all expressions to be equal to 0
            Constraints::with_selector(sel, expressions)
        });

        // create 4 gates, each processing a different limb
        for idx in 0..4 {
            // compose the bits of a 64-bit limb into a field element and shift the
            // limb to the left depending in the limb's index `idx`
            meta.create_gate("compose limb", |meta| {
                let mut sum_total = Expression::Constant(F::from(0));

                for i in 0..CELLS_PER_ROW {
                    // the first bit is the highest bit. It is multiplied by the
                    // highest power of 2 for that limb.
                    let bit = meta.query_advice(cfg.bits[i], Rotation::cur());
                    sum_total = sum_total + bit * pow_2_x[255 - (CELLS_PER_ROW * idx) - i].clone();
                }

                // constrain to match the expected value
                let expected = meta.query_advice(cfg.expected_limbs, Rotation::cur());
                let sel = meta.query_selector(cfg.selector_compose[idx]);
                vec![sel * (sum_total - expected)]
            });
        }

        // sums 4 cells
        meta.create_gate("sum4", |meta| {
            let mut sum = Expression::Constant(F::from(0));

            for i in 0..4 {
                let dot_product = meta.query_advice(cfg.scratch_space[i], Rotation::cur());
                sum = sum + dot_product;
            }

            // constrain to match the expected value
            let expected = meta.query_advice(cfg.scratch_space[4], Rotation::cur());
            let sel = meta.query_selector(cfg.selector_sum4);
            vec![sel * (sum - expected)]
        });

        // sums 2 cells
        meta.create_gate("sum2", |meta| {
            let mut sum = Expression::Constant(F::from(0));

            for i in 0..2 {
                let dot_product = meta.query_advice(cfg.scratch_space[i], Rotation::cur());
                sum = sum + dot_product;
            }

            // constrain to match the expected value
            let expected = meta.query_advice(cfg.scratch_space[4], Rotation::cur());
            let sel = meta.query_selector(cfg.selector_sum2);
            vec![sel * (sum - expected)]
        });

        // left-shifts the first cell by SALT_SIZE and adds the second cell (the salt)
        meta.create_gate("add salt", |meta| {
            let cell = meta.query_advice(cfg.scratch_space[0], Rotation::cur());
            let salt = meta.query_advice(cfg.scratch_space[1], Rotation::cur());
            let sum = cell * pow_2_x[SALT_SIZE].clone() + salt;

            // constrain to match the expected value
            let expected = meta.query_advice(cfg.scratch_space[4], Rotation::cur());
            let sel = meta.query_selector(cfg.selector_add_salt);
            vec![sel * (sum - expected)]
        });

        cfg
    }

    /// Creates the circuit
    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let (label_sum, plaintext) = layouter.assign_region(
            || "main",
            |mut region| {
                // dot products for each row
                let mut assigned_dot_products = Vec::new();
                // limb for each row
                let mut assigned_limbs = Vec::new();
                //salt
                let assigned_salt =
                    region.assign_advice(|| "", cfg.salt, 0, || Value::known(self.salt))?;

                for j in 0..FULL_FIELD_ELEMENTS + 1 {
                    // decompose the private field element into bits
                    let bits = bigint_to_256bits(f_to_bigint(&self.plaintext[j].clone()));

                    // The last field element consists of only 2 64-bit limbs,
                    // so we use 2 rows for its bits and we skip processing the
                    // 2 high limbs
                    let max_row = if j == FULL_FIELD_ELEMENTS { 2 } else { 4 };
                    let skip = if j == FULL_FIELD_ELEMENTS { 2 } else { 0 };

                    for row in 0..max_row {
                        // convert bits into field elements and put them on the same row
                        for i in 0..CELLS_PER_ROW {
                            region.assign_advice(
                                || "",
                                cfg.bits[i],
                                j * 4 + row,
                                || Value::known(F::from(bits[CELLS_PER_ROW * (row + skip) + i])),
                            )?;
                        }
                        // constrain the whole row of bits to be binary
                        cfg.selector_binary_check.enable(&mut region, j * 4 + row)?;

                        let limbs = bits_to_limbs(bits);
                        // place expected limbs for each row
                        assigned_limbs.push(region.assign_advice(
                            || "",
                            cfg.expected_limbs,
                            j * 4 + row,
                            || Value::known(bigint_to_f(&limbs[row + skip].clone())),
                        )?);
                        // constrain the expected limb to match what the gate
                        // composes from bits
                        cfg.selector_compose[row + skip].enable(&mut region, j * 4 + row)?;

                        // compute the expected dot product for this row
                        let mut dot_product = F::from(0);
                        for i in 0..CELLS_PER_ROW {
                            dot_product += self.deltas[j * 4 + row][i]
                                * F::from(bits[CELLS_PER_ROW * (row + skip) + i]);
                        }

                        // place it into a cell for the expected dot_product
                        assigned_dot_products.push(region.assign_advice(
                            || "",
                            cfg.dot_product,
                            j * 4 + row,
                            || Value::known(dot_product),
                        )?);
                        // constrain the expected dot product to match what the gate computes
                        cfg.selector_dot_product.enable(&mut region, j * 4 + row)?;
                    }
                }

                // the grand sum of all dot products
                // safe to .unwrap because we will always have exactly 58 dot_product
                let (dot_product, mut offset) = self.compute_58_cell_sum(
                    &assigned_dot_products.try_into().unwrap(),
                    &mut region,
                    &cfg,
                    0,
                )?;

                // move `zero_sum` into `scratch_space` area to be used in computations
                let zero_sum = region.assign_advice_from_instance(
                    || "",
                    cfg.public_inputs,
                    2,
                    cfg.scratch_space[0],
                    offset,
                )?;
                offset += 1;

                // add zero_sum to all dot_products to get label_sum
                let label_sum =
                    self.fold_sum(&[vec![dot_product, zero_sum]], &mut region, &cfg, offset)?[0]
                        .clone();
                offset += 1;

                // add salt
                let label_sum_salted =
                    self.add_salt(label_sum, assigned_salt.clone(), &mut region, &cfg, offset)?;
                offset += 1;

                // Constrains each chunks of 4 limbs to be equal to a cell and
                // returns the constrained cells containing the original plaintext
                // (the private input to the circuit).
                let plaintext: Result<Vec<AssignedCell<F, F>>, Error> = assigned_limbs
                    .chunks(4)
                    .map(|c| {
                        let sum =
                            self.fold_sum(&[c.to_vec()], &mut region, &cfg, offset)?[0].clone();
                        offset += 1;
                        Ok(sum)
                    })
                    .collect();
                let mut plaintext = plaintext?;

                // add salt to the last field element of the plaintext
                let pt_len = plaintext.len();
                let last_with_salt = self.add_salt(
                    plaintext[pt_len - 1].clone(),
                    assigned_salt,
                    &mut region,
                    &cfg,
                    offset,
                )?;
                // uncomment if we need to do more computations in the scratch space
                // offset += 1;

                // replace the last field element with the one with salt
                plaintext[pt_len - 1] = last_with_salt;

                //println!("{:?} final `scratch_space` offset", offset);
                Ok((label_sum_salted, plaintext))
            },
        )?;

        // Hash the label sum and constrain the digest to match the public input

        let chip = Pow5Chip::construct(cfg.poseidon_config_rate1.clone());

        let hasher = Hash::<F, _, Spec1, ConstantLength<1>, 2, 1>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        let output = hasher.hash(layouter.namespace(|| "hash"), [label_sum])?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected = region.assign_advice_from_instance(
                    || "",
                    cfg.public_inputs,
                    1,
                    cfg.advice_from_instance,
                    0,
                )?;
                region.constrain_equal(output.cell(), expected.cell())?;
                Ok(())
            },
        )?;

        // Hash the plaintext and constrain the digest to match the public input

        let chip = Pow5Chip::construct(cfg.poseidon_config_rate15.clone());

        let hasher = Hash::<F, _, Spec15, ConstantLength<15>, 16, 15>::init(
            chip,
            layouter.namespace(|| "init"),
        )?;
        // unwrap() is safe since we use exactly 15 field elements in plaintext
        let output = hasher.hash(layouter.namespace(|| "hash"), plaintext.try_into().unwrap())?;

        layouter.assign_region(
            || "constrain output",
            |mut region| {
                let expected = region.assign_advice_from_instance(
                    || "",
                    cfg.public_inputs,
                    0,
                    cfg.advice_from_instance,
                    1,
                )?;
                region.constrain_equal(output.cell(), expected.cell())?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl AuthDecodeCircuit {
    pub fn new(plaintext: [F; 15], salt: F, deltas: [[F; CELLS_PER_ROW]; USEFUL_ROWS]) -> Self {
        Self {
            plaintext,
            salt,
            deltas,
        }
    }
    // Computes the sum of 58 `cells` and outputs the cell containing the sum
    // and the amount of rows used up during computation.
    // Computations are done in the `scratch_space` area starting at the `row_offset`
    // row. Constrains all intermediate values as necessary, so that
    // the resulting cell is a properly constrained sum.
    fn compute_58_cell_sum(
        &self,
        cells: &[AssignedCell<F, F>; 58],
        region: &mut Region<F>,
        config: &TopLevelConfig,
        row_offset: usize,
    ) -> Result<(AssignedCell<F, F>, usize), Error> {
        let original_offset = row_offset;
        let mut offset = row_offset;

        // copy chunks of 4 cells to `scratch_space` and compute their sums
        let l1_chunks: Vec<Vec<AssignedCell<F, F>>> = cells.chunks(4).map(|c| c.to_vec()).collect();

        // do not process the last chunk of level1 as it will be
        // later combined with the last chunk of level2
        let l2_sums = self.fold_sum(&l1_chunks[..l1_chunks.len() - 1], region, config, offset)?;

        offset += l1_chunks.len() - 1;

        // we now have 14 level-2 subsums which need to be summed with each
        // other in batches of 4. There are 2 subsums from level 1 which we
        // will combine with level 2 subsums.

        let l2_chunks: Vec<Vec<AssignedCell<F, F>>> =
            l2_sums.chunks(4).map(|c| c.to_vec()).collect();

        // do not process the last chunk as it will be combined with
        // level1's last chunk's sums
        let mut l3_sums =
            self.fold_sum(&l2_chunks[..l2_chunks.len() - 1], region, config, offset)?;

        offset += l2_chunks.len() - 1;

        // we need to find the sum of level1's last chunk's 2 elements and level2's
        // last chunks 2 elements
        let chunk = [
            l1_chunks[l1_chunks.len() - 1][0].clone(),
            l1_chunks[l1_chunks.len() - 1][1].clone(),
            l2_chunks[l2_chunks.len() - 1][0].clone(),
            l2_chunks[l2_chunks.len() - 1][1].clone(),
        ];
        let sum = self.fold_sum(&[chunk.to_vec()], region, config, offset)?;

        offset += 1;

        l3_sums.push(sum[0].clone());

        // 4 level-3 subsums into the final level-4 sum which is the final
        // sum

        let l3_chunks: Vec<Vec<AssignedCell<F, F>>> =
            l3_sums.chunks(4).map(|c| c.to_vec()).collect();

        let final_sum = self.fold_sum(&l3_chunks, region, config, offset)?[0].clone();

        offset += 1;

        Ok((final_sum, offset - original_offset))
    }

    // Puts the cells on the same row and computes their sum. Places the resulting
    // cell into the 5th column of the `scratch_space` and returns it. Returns
    // as many sums as there are chunks of cells.
    fn fold_sum(
        &self,
        chunks: &[Vec<AssignedCell<F, F>>],
        region: &mut Region<F>,
        config: &TopLevelConfig,
        row_offset: usize,
    ) -> Result<Vec<AssignedCell<F, F>>, Error> {
        (0..chunks.len())
            .map(|i| {
                let size = chunks[i].len();
                assert!(size == 2 || size == 4);

                let mut sum = Value::known(F::from(0));
                // copy the cells onto the same row
                for j in 0..size {
                    chunks[i][j].copy_advice(
                        || "",
                        region,
                        config.scratch_space[j],
                        row_offset + i,
                    )?;
                    sum = sum + chunks[i][j].value();
                }
                let assigned_sum =
                    region.assign_advice(|| "", config.scratch_space[4], row_offset + i, || sum)?;

                // activate the gate which performs the actual constraining
                if size == 4 {
                    config.selector_sum4.enable(region, row_offset + i)?;
                } else {
                    config.selector_sum2.enable(region, row_offset + i)?;
                }

                Ok(assigned_sum)
            })
            .collect()
    }

    // Puts two cells on the same row. The second cell is the salt. Left-shifts
    // the first cell's value by the size of the salt and adds the salt to it.
    // Places the resulting cell into the 5th column of the `scratch_space` and
    // returns it.
    fn add_salt(
        &self,
        cell: AssignedCell<F, F>,
        salt: AssignedCell<F, F>,
        region: &mut Region<F>,
        config: &TopLevelConfig,
        row_offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        // copy the cells onto the same row
        cell.copy_advice(|| "", region, config.scratch_space[0], row_offset)?;
        salt.copy_advice(|| "", region, config.scratch_space[1], row_offset)?;

        // compute the expected sum and put it into the 5th cell
        let two = BigUint::from(2u8);
        let pow_2_salt = bigint_to_f(&two.pow(SALT_SIZE as u32));
        let sum = cell.value() * Value::known(pow_2_salt) + salt.value();
        let assigned_sum =
            region.assign_advice(|| "", config.scratch_space[4], row_offset, || sum)?;

        // activate the gate which performs the actual constraining
        config.selector_add_salt.enable(region, row_offset)?;

        Ok(assigned_sum)
    }
}

/// The circuit is tested from [super::prover::tests]
#[cfg(test)]
mod tests {}
