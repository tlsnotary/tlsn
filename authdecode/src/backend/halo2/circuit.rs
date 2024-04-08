use halo2_poseidon::poseidon::{primitives::ConstantLength, Hash, Pow5Chip, Pow5Config};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr as F,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};
use num::BigUint;
use std::convert::TryInto;

use super::{
    poseidon::{
        circuit_config::{
            configure_poseidon_rate_1, configure_poseidon_rate_15, configure_poseidon_rate_2,
        },
        spec::{Spec1, Spec15, Spec2},
    },
    utils::{compose_bits, f_to_bits},
};

/// Rationale for the selection of constants.
///
/// In order to optimize the proof generation time, the circuit should contain as few instance
/// columns as possible and also as few rows as possible.
/// The circuit has [super::CHUNK_SIZE] public inputs (deltas) which must be placed into instance
/// columns. It was empirically established that 58 rows and 64 instance columns provides the best
/// performance.
///
/// Note that 58 usable rows is what we get when we set the circuit's K to 6 (halo2 reserves 6 rows
/// for internal purposes, so we get 2^6-6 usable rows).

/// How many field elements to use to pack the plaintext into. Only [USABLE_BITS] of each field element
/// will be used.  
pub const FIELD_ELEMENTS: usize = 14;

/// How many LSBs of a field element to use to pack the plaintext into.
pub const USABLE_BITS: usize = 253;

/// How many advice columns are there to put the plaintext bits into.
///
/// Note that internally the bits of one plaintext field element are zero-padded on the left to a
/// total of 256 bits. Then the bits are split up into 4 limbs of 64 bits. Each limb's bits are
/// placed on an individual row.
pub const BIT_COLUMNS: usize = 64;

/// The amount of rows that the circuit is allowed to use.
///
/// When K == 6, halo2 reserves 6 rows internally, which leaves us with 2^K - 6 = 58 usable rows.
pub const USABLE_ROWS: usize = 56;

/// Bitsize of salt used both in the plaintext commitment and encoding sum commitment.
pub const SALT_SIZE: usize = 128;

#[derive(Clone, Debug)]
/// The circuit configuration.
pub struct CircuitConfig {
    /// Columns to put the plaintext bits into.  
    bits: [Column<Advice>; BIT_COLUMNS],
    /// Scratch space used to calculate intermediate values.
    scratch_space: [Column<Advice>; 5],
    /// Expected dot product of a vector of deltas and a vector of limb's bits.
    dot_product: Column<Advice>,
    /// Expected value when composing a 64-bit limb into a field element.
    expected_composed_limbs: Column<Advice>,
    /// The first and the second rows of this column are used to store the plaintext salt and the
    /// encoding sum salt, resp.
    salt: Column<Advice>,

    /// Columns of deltas, such that each row of deltas corresponds to one limb of plaintext.
    deltas: [Column<Instance>; BIT_COLUMNS],

    /// Since halo2 does not allow to constrain inputs in instance columns
    /// directly, we first need to copy the inputs into this advice column.
    advice_from_instance: Column<Advice>,

    // SELECTORS.
    // For a description of what constraint is activated when a selector is enabled, consult the
    // description of the gate which uses the selector. e.g. for "selector_dot_product" consult the
    // gate "dot_product" etc.
    selector_dot_product: Selector,
    selector_binary_check: Selector,
    selector_compose_limb: [Selector; 4],
    selector_sum: Selector,
    selector_three_bits_zero: Selector,

    /// Config for rate-15 Poseidon.
    poseidon_config_rate15: Pow5Config<F, 16, 15>,
    /// Config for rate-2 Poseidon.
    poseidon_config_rate2: Pow5Config<F, 3, 2>,

    /// Contains the following public inputs in this order: (plaintext hash, encoding sum hash,
    /// zero sum).
    public_inputs: Column<Instance>,
}

#[derive(Clone, Debug)]
/// The AuthDecode circuit.
pub struct AuthDecodeCircuit {
    /// The bits of plaintext which was committed to. Each bit is a field element.
    ///
    /// The original plaintext consisted of [FIELD_ELEMENTS] field elements.
    /// Each field element is split into 4 limbs of [BIT_COLUMNS] bits starting from the high limb.
    pub plaintext: [[F; BIT_COLUMNS]; FIELD_ELEMENTS * 4],
    /// Salt used to create a plaintext commitment.
    pub plaintext_salt: F,
    /// Salt used to create an encoding sum commitment.
    pub encoding_sum_salt: F,
}

impl Circuit<F> for AuthDecodeCircuit {
    type Config = CircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            plaintext: [[F::default(); BIT_COLUMNS]; FIELD_ELEMENTS * 4],
            plaintext_salt: F::default(),
            encoding_sum_salt: F::default(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // ADVICE COLUMNS

        let bits: [Column<Advice>; BIT_COLUMNS] = (0..BIT_COLUMNS)
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

        let deltas: [Column<Instance>; BIT_COLUMNS] = (0..BIT_COLUMNS)
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
        let selector_sum = meta.selector();
        let selector_three_bits_zero = meta.selector();

        // POSEIDON

        let poseidon_config_rate15 = configure_poseidon_rate_15::<Spec15>(15, meta);
        let poseidon_config_rate2 = configure_poseidon_rate_2::<Spec2>(2, meta);
        // We need to designate one column for global constants which the Poseidon chip requires.
        let global_constants = meta.fixed_column();
        meta.enable_constant(global_constants);

        // Put everything initialized above into a config.
        let cfg = CircuitConfig {
            bits,
            scratch_space,
            dot_product,
            expected_composed_limbs: expected_limbs,
            salt,
            advice_from_instance,

            deltas,

            selector_dot_product,
            selector_compose_limb: selector_compose,
            selector_binary_check,
            selector_sum,
            selector_three_bits_zero,

            poseidon_config_rate15,
            poseidon_config_rate2,

            public_inputs,
        };

        // MISC

        // Build `Expression`s containing powers of 2 from the 0th to the 255th power.
        let mut pow_2_x: Vec<F> = Vec::with_capacity(256);
        let two = F::one() + F::one();
        // Push 2^0.
        pow_2_x.push(F::one());

        for n in 1..256 {
            // Push 2^n.
            pow_2_x.push(pow_2_x[n - 1] * two);
        }

        let pow_2_x = pow_2_x
            .into_iter()
            .map(Expression::Constant)
            .collect::<Vec<_>>();

        // GATES

        // Computes the dot product of a vector of deltas and a vector of a limb's bitsa and
        // constrains it to match the expected dot product.
        meta.create_gate("dot_product", |meta| {
            let mut product = Expression::Constant(F::from(0));

            for i in 0..BIT_COLUMNS {
                let delta = meta.query_instance(cfg.deltas[i], Rotation::cur());
                let bit = meta.query_advice(cfg.bits[i], Rotation::cur());
                product = product + delta * bit;
            }

            // Constrain to match the expected dot product.
            let expected = meta.query_advice(cfg.dot_product, Rotation::cur());
            let sel = meta.query_selector(cfg.selector_dot_product);
            vec![sel * (product - expected)]
        });

        // Constrains each bit of a limb to be binary.
        meta.create_gate("binary_check", |meta| {
            // Create an `Expression` for each bit.
            let expressions: [Expression<F>; BIT_COLUMNS] = (0..BIT_COLUMNS)
                .map(|i| {
                    let bit = meta.query_advice(cfg.bits[i], Rotation::cur());
                    bit.clone() * bit.clone() - bit
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();
            let sel = meta.query_selector(cfg.selector_binary_check);

            // Constrain all expressions to be equal to 0.
            Constraints::with_selector(sel, expressions)
        });

        // Create 4 gates for each of the 4 limbs of the plaintext bits, starting from the high limb.
        for idx in 0..4 {
            // Compose the bits of a limb into a field element, left-shifting if necessary and
            // constrain the result to match the expected value.
            meta.create_gate("compose_limb", |meta| {
                let mut sum_total = Expression::Constant(F::from(0));

                for i in 0..BIT_COLUMNS {
                    // The first bit is the highest bit. It is multiplied by the
                    // highest power of 2 for that limb.
                    let bit = meta.query_advice(cfg.bits[i], Rotation::cur());
                    sum_total = sum_total + bit * pow_2_x[255 - (BIT_COLUMNS * idx) - i].clone();
                }

                // Constrain to match the expected limb value.
                let expected = meta.query_advice(cfg.expected_composed_limbs, Rotation::cur());
                let sel = meta.query_selector(cfg.selector_compose_limb[idx]);
                vec![sel * (sum_total - expected)]
            });
        }

        // Sums 4 cells in the scratch space and constrains the sum to equal the expected value.
        meta.create_gate("sum", |meta| {
            let mut sum = Expression::Constant(F::from(0));

            for i in 0..4 {
                let value = meta.query_advice(cfg.scratch_space[i], Rotation::cur());
                sum = sum + value;
            }

            // Constrain to match the expected sum.
            let expected = meta.query_advice(cfg.scratch_space[4], Rotation::cur());
            let sel = meta.query_selector(cfg.selector_sum);
            vec![sel * (sum - expected)]
        });

        // Constrains 3 most significant bits of a limb to be zero.
        meta.create_gate("three_bits_zero", |meta| {
            let expressions: [Expression<F>; 3] = (0..3)
                .map(|i| meta.query_advice(cfg.bits[i], Rotation::cur()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let sel = meta.query_selector(cfg.selector_three_bits_zero);

            // Constrain all expressions to be equal to 0.
            Constraints::with_selector(sel, expressions)
        });

        cfg
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let (expected_plaintext_hash, expected_encoding_sum_hash, zero_sum) = layouter
            .assign_region(
                || "assign advice from instance",
                |mut region| {
                    let expected_plaintext_hash = region.assign_advice_from_instance(
                        || "assign plaintext hash",
                        cfg.public_inputs,
                        0,
                        cfg.advice_from_instance,
                        0,
                    )?;

                    let expected_encoding_sum_hash = region.assign_advice_from_instance(
                        || "assign encoding sum hash",
                        cfg.public_inputs,
                        1,
                        cfg.advice_from_instance,
                        1,
                    )?;

                    let zero_sum = region.assign_advice_from_instance(
                        || "assign zero sum",
                        cfg.public_inputs,
                        2,
                        cfg.advice_from_instance,
                        2,
                    )?;

                    Ok((
                        expected_plaintext_hash,
                        expected_encoding_sum_hash,
                        zero_sum,
                    ))
                },
            )?;

        let (encoding_sum_salted, plaintext_salted) = layouter.assign_region(
            || "main",
            |mut region| {
                // Expected dot product for each vector of limb's bits and a corresponding vector
                // of deltas.
                let mut expected_dot_products = Vec::new();
                // Expected value of each limb composed into a field element.
                let mut expected_composed_limbs = Vec::new();

                // Assign plaintext salt to an advice column.
                let plaintext_salt = region.assign_advice(
                    || "assign plaintext salt",
                    cfg.salt,
                    0,
                    || Value::known(self.plaintext_salt),
                )?;

                // Assign encoding sum salt to an advice column.
                let encoding_sum_salt = region.assign_advice(
                    || "assign encoding sum salt",
                    cfg.salt,
                    1,
                    || Value::known(self.encoding_sum_salt),
                )?;

                for j in 0..FIELD_ELEMENTS {
                    // It is safe to `unwrap` since there are always exactly FIELD_ELEMENTS * 4 limbs.
                    let limb_bits: &[[F; 64]; 4] =
                        &self.plaintext[j * 4..(j + 1) * 4].try_into().unwrap();

                    // Process each limb's bits.
                    for (limb_idx, limb_bits) in limb_bits.into_iter().enumerate() {
                        // Assign all bits of the same limb to the same row.
                        for i in 0..BIT_COLUMNS {
                            region.assign_advice(
                                || "assign limb bits",
                                cfg.bits[i],
                                j * 4 + limb_idx,
                                || Value::known(limb_bits[i]),
                            )?;
                        }
                        // Constrain the whole row of bits to be binary.
                        cfg.selector_binary_check
                            .enable(&mut region, j * 4 + limb_idx)?;

                        if limb_idx == 0 {
                            // Constrain the high limb's 3 MSBs to be zero.
                            cfg.selector_three_bits_zero
                                .enable(&mut region, j * 4 + limb_idx)?;
                        }

                        let expected_limb = compose_bits(&limb_bits, limb_idx);
                        // Assign the expected composed limb.
                        expected_composed_limbs.push(region.assign_advice(
                            || "assign the expected composed limb",
                            cfg.expected_composed_limbs,
                            j * 4 + limb_idx,
                            || Value::known(expected_limb),
                        )?);

                        // Constrain the expected limb to match the value which the gate composes.
                        cfg.selector_compose_limb[limb_idx]
                            .enable(&mut region, j * 4 + limb_idx)?;

                        // Compute and assign the expected dot product.
                        let mut expected_dot_product = Value::known(F::zero());
                        for i in 0..BIT_COLUMNS {
                            let delta = region.instance_value(cfg.deltas[i], j * 4 + limb_idx)?;
                            expected_dot_product =
                                expected_dot_product + delta * Value::known(F::from(limb_bits[i]));
                        }

                        expected_dot_products.push(region.assign_advice(
                            || "assign expected dot product",
                            cfg.dot_product,
                            j * 4 + limb_idx,
                            || expected_dot_product,
                        )?);

                        // Constrain the expected dot product to match the value which the gate
                        // computes.
                        cfg.selector_dot_product
                            .enable(&mut region, j * 4 + limb_idx)?;
                    }
                }

                // Row offset of the scratch space.
                let mut offset = 0;

                // Compute the grand sum of all dot products.
                // It is safe to .unwrap since there will always be exactly 56 dot products.
                let dot_product = self.sum_56_cells(
                    &expected_dot_products.try_into().unwrap(),
                    &mut region,
                    &cfg,
                    offset,
                )?;
                // 19 rows of scratch space will be used to sum 56 values.
                offset += 19;

                // Add zero sum and the grand dot products to get encoding sum.
                let encoding_sum =
                    self.sum(&[dot_product, zero_sum.clone()], &mut region, &cfg, offset)?;
                offset += 1;

                let encoding_sum_salted = vec![encoding_sum, encoding_sum_salt];

                let plaintext: Result<Vec<AssignedCell<F, F>>, Error> = expected_composed_limbs
                    .chunks(4)
                    .map(|c| {
                        // Sum 4 limbs to get the plaintext field element.
                        let field_element = self.sum(c, &mut region, &cfg, offset)?;
                        offset += 1;
                        Ok(field_element)
                    })
                    .collect();
                let mut plaintext = plaintext?;

                plaintext.push(plaintext_salt);

                Ok((encoding_sum_salted, plaintext))
            },
        )?;

        // Hash the salted encoding sum and constrain the digest to match the expected value.
        let chip = Pow5Chip::construct(cfg.poseidon_config_rate2.clone());
        let hasher = Hash::<F, _, Spec2, ConstantLength<2>, 3, 2>::init(
            chip,
            layouter.namespace(|| "init spec2 poseidon"),
        )?;

        let output = hasher.hash(
            layouter.namespace(|| "hash spec2 poseidon"),
            encoding_sum_salted.try_into().unwrap(),
        )?;

        layouter.assign_region(
            || "constrain encoding sum digest",
            |mut region| {
                region.constrain_equal(output.cell(), expected_encoding_sum_hash.cell())?;
                Ok(())
            },
        )?;

        // Hash the salted plaintext and constrain the digest to match the expected value.
        let chip = Pow5Chip::construct(cfg.poseidon_config_rate15.clone());

        let hasher = Hash::<F, _, Spec15, ConstantLength<15>, 16, 15>::init(
            chip,
            layouter.namespace(|| "init spec15 poseidon"),
        )?;
        // unwrap() is safe since we use exactly 15 field elements in plaintext
        let output = hasher.hash(
            layouter.namespace(|| "hash spec15 poseidon"),
            plaintext_salted.try_into().unwrap(),
        )?;

        layouter.assign_region(
            || "constrain plaintext digest",
            |mut region| {
                region.constrain_equal(output.cell(), expected_plaintext_hash.cell())?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl AuthDecodeCircuit {
    pub fn new(plaintext: [F; FIELD_ELEMENTS], plaintext_salt: F, encoding_sum_salt: F) -> Self {
        // Split each field element into 4 64-bit limbs, starting from the high limb.

        Self {
            plaintext: plaintext
                .into_iter()
                .flat_map(|f| {
                    f_to_bits(&f)
                        .into_iter()
                        // Convert each bit into a field element.
                        .map(F::from)
                        .collect::<Vec<_>>()
                        .chunks(BIT_COLUMNS)
                        .map(|chunk| chunk.try_into().unwrap())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            plaintext_salt,
            encoding_sum_salt,
        }
    }

    /// Computes the sum of values in 56 `cells` and outputs the cell containing the sum.
    ///
    /// All values are copied into the scratch space starting at the `offset` row. All values are
    /// properly constrained.
    fn sum_56_cells(
        &self,
        cells: &[AssignedCell<F, F>; 56],
        region: &mut Region<F>,
        config: &CircuitConfig,
        mut offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        // Split the 56 values into chunks of 4 and compute the sum of each chunk. We will have 14 sums
        // in total.
        let sums_14: Vec<AssignedCell<F, F>> = cells
            .chunks(4)
            .map(|cells| {
                let sum = self.sum(cells, region, config, offset)?;
                offset += 1;
                Ok(sum)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Split the 14 values into chunks of 4 and compute the sum of each chunk. We will have 4 sums
        // in total.
        let sums_4: Vec<AssignedCell<F, F>> = sums_14
            .chunks(4)
            .map(|cells| {
                let sum = self.sum(cells, region, config, offset)?;
                offset += 1;
                Ok(sum)
            })
            .collect::<Result<Vec<_>, Error>>()?;

        // Sum up the 4 values to get the final sum.
        self.sum(&sums_4, region, config, offset)
    }

    /// Computes the sum of values in `cells` and returns a cell with the sum.
    ///
    /// All values are copied into the scratch space starting at the `offset` row. All values are
    /// properly constrained.
    ///
    /// # Panics
    ///
    /// Panics if the amount of `cells` is less than 2 or more than 4.
    fn sum(
        &self,
        cells: &[AssignedCell<F, F>],
        region: &mut Region<F>,
        config: &CircuitConfig,
        row_offset: usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        assert!(cells.len() <= 4 && cells.len() >= 2);

        let mut sum = Value::known(F::zero());
        // Copy the cells onto the same row and compute their sum.
        for (i, cell) in cells.iter().enumerate() {
            cell.copy_advice(
                || "copying summands",
                region,
                config.scratch_space[i],
                row_offset,
            )?;
            sum = sum + cell.value();
        }
        // If there were less that 4 cells to sum, constrain the unused cells to be 0.
        for i in cells.len()..4 {
            region.assign_advice_from_constant(
                || "assigning zero values",
                config.scratch_space[i],
                row_offset,
                F::from(0),
            )?;
        }
        let assigned_sum = region.assign_advice(
            || "assigning the sum",
            config.scratch_space[4],
            row_offset,
            || sum,
        )?;

        config.selector_sum.enable(region, row_offset)?;

        Ok(assigned_sum)
    }
}

#[cfg(test)]
mod tests {
    use halo2_proofs::dev::MockProver;
    use rand::Rng;
    use rand_chacha::ChaCha12Rng;
    use rand_core::SeedableRng;
    /// The size of plaintext in bytes;
    const PLAINTEXT_SIZE: usize = 1000;

    fn test() {
        let mut rng = ChaCha12Rng::from_seed([0; 32]);

        // Generate random plaintext.
        let plaintext: Vec<bool> = core::iter::repeat_with(|| rng.gen::<bool>())
            .take(PLAINTEXT_SIZE * 8)
            .collect();

        // Generate Verifier's full encodings for each bit of the plaintext.
        let mut random = [0u8; PLAINTEXT_SIZE * 8 * 16 * 2];
        for elem in random.iter_mut() {
            *elem = rng.gen();
        }
        let full_encodings = &random
            .chunks(32)
            .map(|pair| [pair[0..16].to_vec(), pair[16..32].to_vec()])
            .collect::<Vec<_>>();

        // Prover's active encodings are based on their choice bits.
        //let active_encodings = choose(full_encodings, &plaintext);

        //MockProver::run
    }
}
