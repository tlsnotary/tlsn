//! Authdecode circuit.

use ff::Field;
use halo2_poseidon::poseidon::{PoseidonInstructions, Pow5Chip, Pow5Config};
use halo2_proofs::{
    circuit::{AssignedCell, Layouter, Region, SimpleFloorPlanner, Value},
    halo2curves::bn256::Fr as F,
    plonk::{
        Advice, Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Instance,
        Selector,
    },
    poly::Rotation,
};
use poseidon_circomlib::CircomlibSpec;
use std::convert::TryInto;

use crate::backend::halo2::{
    poseidon::{configure_poseidon_rate_15, configure_poseidon_rate_3},
    utils::{compose_bits, f_to_bits},
};

// Rationale for the selection of constants.
//
// In order to optimize the proof generation time, the circuit should contain as few instance
// columns as possible and also as few rows as possible.
// The circuit has [super::CHUNK_SIZE] public inputs (deltas) which must be placed into instance
// columns. It was empirically established that 58 rows and 64 instance columns provides the best
// performance.
//
// Note that 58 usable rows is what we get when we set the circuit's K to 6 (halo2 reserves 6 rows
// for internal purposes, so we get 2^6-6 usable rows).

/// How many field elements to use to pack the plaintext into. Only [USABLE_BYTES] of each field
/// element will be used.  
pub const FIELD_ELEMENTS: usize = 14;

/// How many least significant bytes of a field element to use to pack the plaintext into.
pub const USABLE_BYTES: usize = 31;

/// How many bits there are in one limb of a plaintext field element.
pub const BITS_PER_LIMB: usize = 64;

/// Bytesize of the salt used both in the plaintext commitment and encoding sum commitment.
pub const SALT_SIZE: usize = 16;

#[derive(Clone, Debug)]
/// The circuit configuration.
pub struct CircuitConfig {
    /// Columns containing plaintext bits. A row of `bits` consitutes a limb is LSB0 bit order.  
    bits: [Column<Advice>; BITS_PER_LIMB],
    /// Scratch space used to calculate intermediate values.
    scratch_space: [Column<Advice>; 5],
    /// Expected dot product of a vector of deltas and a vector of a limb's bits.
    dot_product: Column<Advice>,
    /// Expected value when composing a 64-bit limb into a field element.
    expected_composed_limbs: Column<Advice>,
    /// The first and the second rows of this column are used to store the plaintext salt and the
    /// encoding sum salt, resp.
    salt: Column<Advice>,

    /// Columns of deltas, arranged such that each row of deltas corresponds to one limb of plaintext.
    deltas: [Column<Instance>; BITS_PER_LIMB],

    /// Contains the following public values in this order: (plaintext hash, encoding sum hash,
    /// zero sum, the zero value).
    advice_from_public: Column<Advice>,

    // SELECTORS.
    // A selector activates a gate with a similar name, e.g. "selector_dot_product" activates the
    // gate "dot_product" etc.
    selector_dot_product: Selector,
    selector_binary_check: Selector,
    selector_compose_limb: [Selector; 4],
    selector_sum: Selector,
    selector_eight_bits_zero: Selector,

    /// Config for rate-15 Poseidon.
    poseidon_config_rate15: Pow5Config<F, 16, 15>,
    /// Config for rate-3 Poseidon.
    poseidon_config_rate3: Pow5Config<F, 4, 3>,

    /// Contains the following public inputs in this order: (plaintext hash, encoding sum hash,
    /// zero sum).
    public_inputs: Column<Instance>,
}

#[derive(Clone, Debug)]
/// The AuthDecode circuit.
pub struct AuthDecodeCircuit {
    /// The bits of plaintext committed to.
    ///
    /// The bits are arranged into 4 limbs. The low limb has index 0. The limbs have LSB0 bit order.
    /// Each individual bit is represented by a field element.
    pub plaintext: [[[F; BITS_PER_LIMB]; 4]; FIELD_ELEMENTS],
    /// The salt used to create a plaintext commitment.
    pub plaintext_salt: F,
    /// The salt used to create an encoding sum commitment.
    pub encoding_sum_salt: F,
}

impl Circuit<F> for AuthDecodeCircuit {
    type Config = CircuitConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            plaintext: [[[F::default(); BITS_PER_LIMB]; 4]; FIELD_ELEMENTS],
            plaintext_salt: F::default(),
            encoding_sum_salt: F::default(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        // ADVICE COLUMNS

        let bits: [Column<Advice>; BITS_PER_LIMB] = (0..BITS_PER_LIMB)
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

        let deltas: [Column<Instance>; BITS_PER_LIMB] = (0..BITS_PER_LIMB)
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
        let selector_eight_bits_zero = meta.selector();

        // POSEIDON

        let poseidon_config_rate15 = configure_poseidon_rate_15(meta);
        let poseidon_config_rate3 = configure_poseidon_rate_3(meta);
        // We need to have one column for global constants which the Poseidon chip requires.
        let global_constants = meta.fixed_column();
        meta.enable_constant(global_constants);

        // Put everything initialized above into a config.
        let cfg = CircuitConfig {
            bits,
            scratch_space,
            dot_product,
            expected_composed_limbs: expected_limbs,
            salt,
            advice_from_public: advice_from_instance,

            deltas,

            selector_dot_product,
            selector_compose_limb: selector_compose,
            selector_binary_check,
            selector_sum,
            selector_eight_bits_zero,

            poseidon_config_rate15,
            poseidon_config_rate3,

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

        // Computes the dot product of a vector of deltas and a vector of a limb's bits and
        // constrains it to match the expected dot product.
        meta.create_gate("dot_product", |meta| {
            let mut product = Expression::Constant(F::zero());

            for i in 0..BITS_PER_LIMB {
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
            let expressions: [Expression<F>; BITS_PER_LIMB] = (0..BITS_PER_LIMB)
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

        // Create 4 gates for each of the 4 limbs of the plaintext bits, starting from the low limb.
        for idx in 0..4 {
            // Compose the bits of a limb into a field element, left-shifting if necessary and
            // constrain the result to match the expected value.
            meta.create_gate("compose_limb", |meta| {
                let mut sum_total = Expression::Constant(F::zero());

                for i in 0..BITS_PER_LIMB {
                    // The lowest bit is multiplied by the lowest power of 2 for that limb.
                    let bit = meta.query_advice(cfg.bits[i], Rotation::cur());
                    sum_total = sum_total + bit * pow_2_x[BITS_PER_LIMB * idx + i].clone();
                }

                // Constrain to match the expected limb value.
                let expected = meta.query_advice(cfg.expected_composed_limbs, Rotation::cur());
                let sel = meta.query_selector(cfg.selector_compose_limb[idx]);
                vec![sel * (sum_total - expected)]
            });
        }

        // Sums 4 cells in the scratch space and constrains the sum to equal the expected value.
        meta.create_gate("sum", |meta| {
            let mut sum = Expression::Constant(F::zero());

            for i in 0..4 {
                let value = meta.query_advice(cfg.scratch_space[i], Rotation::cur());
                sum = sum + value;
            }

            // Constrain to match the expected sum.
            let expected = meta.query_advice(cfg.scratch_space[4], Rotation::cur());
            let sel = meta.query_selector(cfg.selector_sum);
            vec![sel * (sum - expected)]
        });

        // Constrains 8 most significant bits of a limb to be zero.
        meta.create_gate("eight_bits_zero", |meta| {
            let expressions: [Expression<F>; 8] = (0..8)
                .map(|i| meta.query_advice(cfg.bits[BITS_PER_LIMB - 1 - i], Rotation::cur()))
                .collect::<Vec<_>>()
                .try_into()
                .unwrap();

            let sel = meta.query_selector(cfg.selector_eight_bits_zero);

            // Constrain all expressions to be equal to 0.
            Constraints::with_selector(sel, expressions)
        });

        cfg
    }

    fn synthesize(&self, cfg: Self::Config, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let (
            expected_plaintext_hash,
            expected_encoding_sum_hash,
            zero_sum,
            plaintext_salt,
            encoding_sum_salt,
            zero_cell,
        ) = layouter.assign_region(
            || "assign advice",
            |mut region| {
                let expected_plaintext_hash = region.assign_advice_from_instance(
                    || "assign plaintext hash",
                    cfg.public_inputs,
                    0,
                    cfg.advice_from_public,
                    0,
                )?;

                let expected_encoding_sum_hash = region.assign_advice_from_instance(
                    || "assign encoding sum hash",
                    cfg.public_inputs,
                    1,
                    cfg.advice_from_public,
                    1,
                )?;

                let zero_sum = region.assign_advice_from_instance(
                    || "assign zero sum",
                    cfg.public_inputs,
                    2,
                    cfg.advice_from_public,
                    2,
                )?;

                let plaintext_salt = region.assign_advice(
                    || "assign plaintext salt",
                    cfg.salt,
                    0,
                    || Value::known(self.plaintext_salt),
                )?;

                let encoding_sum_salt = region.assign_advice(
                    || "assign encoding sum salt",
                    cfg.salt,
                    1,
                    || Value::known(self.encoding_sum_salt),
                )?;

                let zero_cell = region.assign_advice_from_constant(
                    || "assign zero value",
                    cfg.advice_from_public,
                    3,
                    F::ZERO,
                )?;

                Ok((
                    expected_plaintext_hash,
                    expected_encoding_sum_hash,
                    zero_sum,
                    plaintext_salt,
                    encoding_sum_salt,
                    zero_cell,
                ))
            },
        )?;

        let (plaintext, encoding_sum) = layouter.assign_region(
            || "compose plaintext and compute encoding sum",
            |mut region| {
                // Plaintext field elements composed from bits.
                let mut plaintext = Vec::new();

                // A dot product of one field element's bits with the corresponding deltas.
                let mut dot_products = Vec::new();

                // Row offset of the scratch space.
                let mut offset = 0;

                // Process 4 limbs of one field element of the plaintext at a time.
                for (field_element_idx, limbs) in self.plaintext.iter().enumerate() {
                    // Expected values of limbs composed from bits.
                    let mut expected_limbs = Vec::with_capacity(4);

                    // Expected dot product for each vector of limb's bits and a corresponding vector
                    // of deltas.
                    let mut expected_dot_products = Vec::with_capacity(4);

                    // Process one limb at a time.
                    for (limb_idx, limb_bits) in limbs.iter().enumerate() {
                        // The index of the row where the bits and deltas are located.
                        let row_idx = field_element_idx * 4 + limb_idx;

                        // Assign all bits of a limb to the same row.
                        for (i, bit) in limb_bits.iter().enumerate() {
                            region.assign_advice(
                                || "assign limb bits",
                                cfg.bits[i],
                                row_idx,
                                || Value::known(*bit),
                            )?;
                        }
                        // Constrain the whole row of bits to be binary.
                        cfg.selector_binary_check.enable(&mut region, row_idx)?;

                        if limb_idx == 3 {
                            // Constrain the high limb's MSBs to be zero.
                            cfg.selector_eight_bits_zero.enable(&mut region, row_idx)?;
                        }

                        let expected_limb = compose_bits(limb_bits, limb_idx);

                        // Assign the expected composed limb.
                        expected_limbs.push(region.assign_advice(
                            || "assign the expected composed limb",
                            cfg.expected_composed_limbs,
                            row_idx,
                            || Value::known(expected_limb),
                        )?);

                        // Constrain the expected limb to match the value which the gate composes.
                        cfg.selector_compose_limb[limb_idx].enable(&mut region, row_idx)?;

                        // Compute and assign the expected dot product for this row.
                        let mut expected_dot_product = Value::known(F::zero());
                        for (i, bit) in limb_bits.iter().enumerate() {
                            let delta = region.instance_value(cfg.deltas[i], row_idx)?;
                            expected_dot_product = expected_dot_product + delta * Value::known(bit);
                        }

                        expected_dot_products.push(region.assign_advice(
                            || "assign expected dot product",
                            cfg.dot_product,
                            row_idx,
                            || expected_dot_product,
                        )?);

                        // Constrain the expected dot product to match the value which the gate
                        // computes.
                        cfg.selector_dot_product.enable(&mut region, row_idx)?;
                    }

                    // Sum 4 limbs to get the plaintext field element.
                    plaintext.push(self.sum(&expected_limbs, &mut region, &cfg, &mut offset)?);

                    // Sum 4 sub dot products to get the dot product of one field element's bits with
                    // the corresponding deltas.
                    dot_products.push(self.sum(
                        &expected_dot_products,
                        &mut region,
                        &cfg,
                        &mut offset,
                    )?);
                }

                // Compute the sub sums for each chunk of 4 sub dot products. We will have 4 sub sums in total.
                // XXX: This is hardcoded to 4 sub sums which is good enough if we have anywhere from 13
                // to 16 field elements of plaintext.
                let four_sums = dot_products
                    .chunks(4)
                    .map(|chunk| self.sum(chunk, &mut region, &cfg, &mut offset))
                    .collect::<Result<Vec<_>, Error>>()?;

                // Compute the final dot product.
                let dot_product = self.sum(&four_sums, &mut region, &cfg, &mut offset)?;

                // Add zero sum and the final dot product to get encoding sum.
                let encoding_sum = self.sum(
                    &[dot_product, zero_sum.clone()],
                    &mut region,
                    &cfg,
                    &mut offset,
                )?;

                Ok((plaintext, encoding_sum))
            },
        )?;

        // Hash the salted encoding sum and constrain the digest to match the expected value.

        let chip = Pow5Chip::construct(cfg.poseidon_config_rate3.clone());

        // Zero-pad the input before hashing.
        // (Normally, we would use a rate-2 Poseidon without padding, but `halo2_poseidon`
        // is not compatible with the Circomlib's rate-2 spec).
        let input = vec![
            encoding_sum.clone(),
            zero_cell.clone(),
            encoding_sum_salt.clone(),
        ];

        type WordRate3 =
            <Pow5Chip<F, 4, 3> as PoseidonInstructions<F, CircomlibSpec<4, 3>, 4, 3>>::Word;

        // Create the state with the first element set to zero.
        let state: [WordRate3; 4] = std::iter::once(zero_cell.clone())
            .chain(input)
            .map(WordRate3::from)
            .collect::<Vec<_>>()
            .try_into()
            .expect("state should have 4 elements");

        let output = PoseidonInstructions::<F, CircomlibSpec<4, 3>, 4, 3>::permute(
            &chip,
            &mut layouter.namespace(|| "permute with rate-3 poseidon"),
            &state,
        )?;

        layouter.assign_region(
            || "constrain plaintext digest",
            |mut region| {
                region.constrain_equal(
                    // circomlib treats the first element of the permuted state as the digest.
                    AssignedCell::<F, F>::from(output[0].clone()).cell(),
                    expected_encoding_sum_hash.cell(),
                )?;
                Ok(())
            },
        )?;

        // Hash the salted plaintext and constrain the digest to match the expected value.

        let chip = Pow5Chip::construct(cfg.poseidon_config_rate15.clone());

        type WordRate15 =
            <Pow5Chip<F, 16, 15> as PoseidonInstructions<F, CircomlibSpec<16, 15>, 16, 15>>::Word;

        // Create the state with the first element set to zero.
        let state: [WordRate15; 16] = std::iter::once(zero_cell)
            .chain(plaintext)
            .chain(std::iter::once(plaintext_salt.clone()))
            .map(WordRate15::from)
            .collect::<Vec<_>>()
            .try_into()
            .expect("state should have 16 elements");

        let output = PoseidonInstructions::<F, CircomlibSpec<16, 15>, 16, 15>::permute(
            &chip,
            &mut layouter.namespace(|| "permute with rate-15 poseidon"),
            &state,
        )?;

        layouter.assign_region(
            || "constrain plaintext digest",
            |mut region| {
                region.constrain_equal(
                    // circomlib treats the first element of the permuted state as the digest.
                    AssignedCell::<F, F>::from(output[0].clone()).cell(),
                    expected_plaintext_hash.cell(),
                )?;
                Ok(())
            },
        )?;

        Ok(())
    }
}

impl AuthDecodeCircuit {
    /// Creates a new AuthDecode circuit.
    pub fn new(plaintext: [F; FIELD_ELEMENTS], plaintext_salt: F, encoding_sum_salt: F) -> Self {
        // Split each field element into 4 limbs. The low limb has index 0.
        Self {
            plaintext: plaintext
                .into_iter()
                .map(|f| {
                    f_to_bits(&f)
                        .into_iter()
                        // Convert each bit into a field element.
                        .map(F::from)
                        .collect::<Vec<_>>()
                        .chunks(BITS_PER_LIMB)
                        .map(|chunk| chunk.try_into().unwrap())
                        .collect::<Vec<[F; BITS_PER_LIMB]>>()
                        .try_into()
                        .unwrap()
                })
                .collect::<Vec<_>>()
                .try_into()
                .unwrap(),
            plaintext_salt,
            encoding_sum_salt,
        }
    }

    /// Calculates the sum of values in `cells` and returns a cell constrained to equal the sum.
    ///    
    /// # Arguments
    /// * `cells` - The cells containing the values to be summed.
    /// * `region` - The halo2 region.
    /// * `config` - The circuit config.
    /// * `row_offset` - The offset of the row in the scratch space on which the calculation
    ///                  will be performed.
    ///
    /// # Panics
    ///
    /// Panics if the amount of `cells` is less than 2 or more than 4.
    fn sum(
        &self,
        cells: &[AssignedCell<F, F>],
        region: &mut Region<F>,
        config: &CircuitConfig,
        row_offset: &mut usize,
    ) -> Result<AssignedCell<F, F>, Error> {
        assert!(cells.len() <= 4 && cells.len() >= 2);

        let mut sum = Value::known(F::zero());
        // Copy the cells onto the same row and compute their sum.
        for (i, cell) in cells.iter().enumerate() {
            cell.copy_advice(
                || "copying summands",
                region,
                config.scratch_space[i],
                *row_offset,
            )?;
            sum = sum + cell.value();
        }
        // If there were less that 4 cells to sum, constrain the unused cells to be 0.
        for i in cells.len()..4 {
            region.assign_advice_from_constant(
                || "assigning zero values",
                config.scratch_space[i],
                *row_offset,
                F::zero(),
            )?;
        }

        let assigned_sum = region.assign_advice(
            || "assigning the sum",
            config.scratch_space[4],
            *row_offset,
            || sum,
        )?;

        config.selector_sum.enable(region, *row_offset)?;

        *row_offset += 1;

        Ok(assigned_sum)
    }
}
