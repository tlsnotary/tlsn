use crate::{
    components::{Feed, GateType, Node},
    types::ValueType,
    Circuit, CircuitBuilder,
};
use regex::{Captures, Regex};
use std::collections::HashMap;

static GATE_PATTERN: &str = r"(?P<input_count>\d+)\s(?P<output_count>\d+)\s(?P<xref>\d+)\s(?:(?P<yref>\d+)\s)?(?P<zref>\d+)\s(?P<gate>INV|AND|XOR)";

#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error("uninitialized feed: {0}")]
    UninitializedFeed(usize),
    #[error("unsupported gate type: {0}")]
    UnsupportedGateType(String),
    #[error(transparent)]
    BuilderError(#[from] crate::BuilderError),
}

impl Circuit {
    /// Parses a circuit in Bristol-fashion format from a file.
    ///
    /// See `https://homes.esat.kuleuven.be/~nsmart/MPC/` for more information.
    ///
    /// # Arguments
    ///
    /// * `filename` - The path to the file to parse.
    /// * `inputs` - The types of the inputs to the circuit.
    /// * `outputs` - The types of the outputs to the circuit.
    ///
    /// # Returns
    ///
    /// The parsed circuit.
    pub fn parse(
        filename: &str,
        inputs: &[ValueType],
        outputs: &[ValueType],
    ) -> Result<Self, ParseError> {
        let file = std::fs::read_to_string(filename)?;

        let builder = CircuitBuilder::new();

        let mut feed_ids: Vec<usize> = Vec::new();
        let mut feed_map: HashMap<usize, Node<Feed>> = HashMap::default();

        let mut input_len = 0;
        for input in inputs {
            let input = builder.add_input_by_type(input.clone());
            for (node, old_id) in input.iter().zip(input_len..input_len + input.len()) {
                feed_map.insert(old_id, *node);
            }
            input_len += input.len();
        }

        let mut state = builder.state().borrow_mut();
        let pattern = Regex::new(GATE_PATTERN).unwrap();
        for cap in pattern.captures_iter(&file) {
            let UncheckedGate {
                xref,
                yref,
                zref,
                gate_type,
            } = UncheckedGate::parse(cap)?;
            feed_ids.push(zref);

            match gate_type {
                GateType::Xor => {
                    let new_x = feed_map
                        .get(&xref)
                        .ok_or(ParseError::UninitializedFeed(xref))?;
                    let new_y = feed_map
                        .get(&yref.unwrap())
                        .ok_or(ParseError::UninitializedFeed(yref.unwrap()))?;
                    let new_z = state.add_xor_gate(*new_x, *new_y);
                    feed_map.insert(zref, new_z);
                }
                GateType::And => {
                    let new_x = feed_map
                        .get(&xref)
                        .ok_or(ParseError::UninitializedFeed(xref))?;
                    let new_y = feed_map
                        .get(&yref.unwrap())
                        .ok_or(ParseError::UninitializedFeed(yref.unwrap()))?;
                    let new_z = state.add_and_gate(*new_x, *new_y);
                    feed_map.insert(zref, new_z);
                }
                GateType::Inv => {
                    let new_x = feed_map
                        .get(&xref)
                        .ok_or(ParseError::UninitializedFeed(xref))?;
                    let new_z = state.add_inv_gate(*new_x);
                    feed_map.insert(zref, new_z);
                }
            }
        }
        drop(state);
        feed_ids.sort();

        for output in outputs.iter().rev() {
            let feeds = feed_ids
                .drain(feed_ids.len() - output.len()..)
                .map(|id| {
                    *feed_map
                        .get(&id)
                        .expect("Old feed should be mapped to new feed")
                })
                .collect::<Vec<Node<Feed>>>();

            let output = output.to_bin_repr(&feeds).unwrap();
            builder.add_output(output);
        }

        Ok(builder.build()?)
    }
}

struct UncheckedGate {
    xref: usize,
    yref: Option<usize>,
    zref: usize,
    gate_type: GateType,
}

impl UncheckedGate {
    fn parse(captures: Captures) -> Result<Self, ParseError> {
        let xref: usize = captures.name("xref").unwrap().as_str().parse()?;
        let yref: Option<usize> = captures
            .name("yref")
            .map(|yref| yref.as_str().parse())
            .transpose()?;
        let zref: usize = captures.name("zref").unwrap().as_str().parse()?;
        let gate_type = captures.name("gate").unwrap().as_str();

        let gate_type = match gate_type {
            "XOR" => GateType::Xor,
            "AND" => GateType::And,
            "INV" => GateType::Inv,
            _ => return Err(ParseError::UnsupportedGateType(gate_type.to_string())),
        };

        Ok(Self {
            xref,
            yref,
            zref,
            gate_type,
        })
    }
}

#[cfg(test)]
mod tests {
    use mpc_circuits_macros::evaluate;

    use super::*;

    #[test]
    fn test_parse_adder_64() {
        let circ = Circuit::parse(
            "circuits/bristol/adder64_reverse.txt",
            &[ValueType::U64, ValueType::U64],
            &[ValueType::U64],
        )
        .unwrap();

        let output: u64 = evaluate!(circ, fn(1u64, 2u64) -> u64).unwrap();

        assert_eq!(output, 3);
    }

    #[test]
    #[cfg(feature = "aes")]
    #[ignore = "expensive"]
    fn test_parse_aes() {
        use aes::{Aes128, BlockEncrypt, NewBlockCipher};

        let circ = Circuit::parse(
            "circuits/bristol/aes_128_reverse.txt",
            &[
                ValueType::Array(Box::new(ValueType::U8), 16),
                ValueType::Array(Box::new(ValueType::U8), 16),
            ],
            &[ValueType::Array(Box::new(ValueType::U8), 16)],
        )
        .unwrap()
        .reverse_input(0)
        .reverse_input(1)
        .reverse_output(0);

        let key = [0u8; 16];
        let msg = [69u8; 16];

        let ciphertext = evaluate!(circ, fn(key, msg) -> [u8; 16]).unwrap();

        let aes = Aes128::new_from_slice(&key).unwrap();
        let mut expected = msg.into();
        aes.encrypt_block(&mut expected);
        let expected: [u8; 16] = expected.into();

        assert_eq!(ciphertext, expected);
    }

    #[test]
    #[cfg(feature = "sha2")]
    #[ignore = "expensive"]
    fn test_parse_sha() {
        use sha2::compress256;

        let circ = Circuit::parse(
            "circuits/bristol/sha256_reverse.txt",
            &[
                ValueType::Array(Box::new(ValueType::U8), 64),
                ValueType::Array(Box::new(ValueType::U32), 8),
            ],
            &[ValueType::Array(Box::new(ValueType::U32), 8)],
        )
        .unwrap()
        .reverse_inputs()
        .reverse_input(0)
        .reverse_input(1)
        .reverse_output(0);

        static SHA2_INITIAL_STATE: [u32; 8] = [
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
            0x5be0cd19,
        ];

        let msg = [69u8; 64];

        let output = evaluate!(circ, fn(SHA2_INITIAL_STATE, msg) -> [u32; 8]).unwrap();

        let mut expected = SHA2_INITIAL_STATE;
        compress256(&mut expected, &[msg.into()]);

        assert_eq!(output, expected);
    }
}
