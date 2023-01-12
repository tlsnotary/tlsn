use crate::{group::UncheckedGroup, Circuit, CircuitError, Gate, ValueType};
use regex::Regex;
use std::{
    fs::File,
    io::{BufRead, BufReader},
    sync::Arc,
};

/// Parses captures into a Vec for convenience
fn line2vec<'a>(re: &Regex, line: &'a str) -> Result<Vec<&'a str>, CircuitError> {
    let v: Vec<&'a str> = re
        .captures_iter(line)
        .map(|cap| {
            let s = cap.get(1).unwrap().as_str();
            s
        })
        .collect();
    Ok(v)
}

impl Circuit {
    /// Parses circuit files in Bristol Fashion format as specified here:
    /// `https://homes.esat.kuleuven.be/~nsmart/MPC/`
    pub fn parse(filename: &str, name: &str, version: &str) -> Result<Arc<Self>, CircuitError> {
        let f = File::open(filename)?;
        let mut reader = BufReader::new(f);

        // Parse first line: ngates nwires\n
        let mut line = String::new();
        let _ = reader
            .read_line(&mut line)
            .map_err(|_| CircuitError::ParsingError("failed to read line".to_string()))?;
        let re = Regex::new(r"(\d+)").expect("Failed to compile regex");
        let line_1 = line2vec(&re, &line)?;

        // Check that first line has 2 values: ngates, nwires
        if line_1.len() != 2 {
            return Err(CircuitError::ParsingError(
                format!("Expecting line to be ngates, nwires: {line}").to_string(),
            ));
        }

        let ngates: usize = line_1[0].parse().map_err(|_| {
            CircuitError::ParsingError(format!("Failed to parse ngates: {}", line_1[0]).to_string())
        })?;
        let wire_count: usize = line_1[1].parse().map_err(|_| {
            CircuitError::ParsingError(format!("Failed to parse nwires: {}", line_1[1]).to_string())
        })?;

        // Parse second line: ninputs input_0_nwires input_1_nwires...
        let mut line = String::new();
        let _ = reader
            .read_line(&mut line)
            .map_err(|_| CircuitError::ParsingError("failed to read line".to_string()))?;
        let re = Regex::new(r"(\d+)\s*").expect("Failed to compile regex");
        let line_2 = line2vec(&re, &line)?;

        // Number of circuit inputs
        let ninputs: usize = line_2[0].parse().map_err(|_| {
            CircuitError::ParsingError(
                format!("Failed to parse ninputs: {}", line_2[0]).to_string(),
            )
        })?;
        let input_nwires: Vec<usize> = line_2[1..]
            .iter()
            .map(|nwires| {
                let nwires: usize = nwires.parse().unwrap();
                nwires
            })
            .collect();

        // Check that nwires is specified for every input
        if input_nwires.len() != ninputs {
            return Err(CircuitError::ParsingError(
                format!("Expecting wire count to be specified for every input: {line}").to_string(),
            ));
        }

        let input_groups = (0..ninputs)
            .map(|id| {
                let start_id = input_nwires[..id].iter().sum();
                let count = input_nwires[id];
                let wires: Vec<usize> = (start_id..start_id + count).collect();
                UncheckedGroup::new(id, "".to_string(), "".to_string(), ValueType::Bits, wires)
            })
            .collect();

        // Parse third line: noutputs output_0_nwires output_1_nwires...
        let mut line = String::new();
        let _ = reader
            .read_line(&mut line)
            .map_err(|_| CircuitError::ParsingError("failed to read line".to_string()))?;
        let re = Regex::new(r"(\d+)\s*").expect("Failed to compile regex");
        let line_3 = line2vec(&re, &line)?;

        // Number of circuit outputs
        let noutputs: usize = line_3[0].parse().map_err(|_| {
            CircuitError::ParsingError(
                format!("Failed to parse noutputs: {}", line_3[0]).to_string(),
            )
        })?;
        let output_nwires: Vec<usize> = line_3[1..]
            .iter()
            .map(|nwires| {
                let nwires: usize = nwires.parse().unwrap();
                nwires
            })
            .collect();

        // Check that nwires is specified for every output
        if output_nwires.len() != noutputs {
            return Err(CircuitError::ParsingError(
                format!(
                    "Expecting wire count to be specified for every output: {}",
                    line
                )
                .to_string(),
            ));
        }

        let output_groups = (0..noutputs)
            .map(|id| {
                let start_id = (wire_count - output_nwires.iter().sum::<usize>())
                    + output_nwires[..id].iter().sum::<usize>();
                let count = output_nwires[id];
                let wires: Vec<usize> = (start_id..start_id + count).collect();
                UncheckedGroup::new(id, "".to_string(), "".to_string(), ValueType::Bits, wires)
            })
            .collect();

        let re = Regex::new(r"(\d+|\S+)\s*").expect("Failed to compile regex");

        let mut id = 0;
        let mut gates = Vec::with_capacity(ngates);

        // Process gates
        for line in reader.lines() {
            let line =
                line.map_err(|_| CircuitError::ParsingError("failed to read line".to_string()))?;
            if line.is_empty() {
                continue;
            }
            let gate_vals = line2vec(&re, &line)?;
            let typ = gate_vals.last().unwrap();
            let gate = match *typ {
                "INV" => {
                    let xref: usize = gate_vals[2].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    let zref: usize = gate_vals[3].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    Gate::Inv { id, xref, zref }
                }
                "AND" => {
                    let xref: usize = gate_vals[2].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    let yref: usize = gate_vals[3].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    let zref: usize = gate_vals[4].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    Gate::And {
                        id,
                        xref,
                        yref,
                        zref,
                    }
                }
                "XOR" => {
                    let xref: usize = gate_vals[2].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    let yref: usize = gate_vals[3].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    let zref: usize = gate_vals[4].parse().map_err(|_| {
                        CircuitError::ParsingError("failed to parse gate".to_string())
                    })?;
                    Gate::Xor {
                        id,
                        xref,
                        yref,
                        zref,
                    }
                }
                _ => {
                    return Err(CircuitError::ParsingError(
                        format!("Encountered unsupported gate type: {}", typ).to_string(),
                    ));
                }
            };
            gates.push(gate);
            id += 1;
        }
        if id != ngates {
            return Err(CircuitError::ParsingError(
                format!("expecting {ngates} gates, parsed {id}").to_string(),
            ));
        }
        Ok(Circuit::new(
            name,
            version,
            input_groups,
            output_groups,
            gates,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_adder64() {
        let circ = Circuit::parse("circuits/bristol/adder64.txt", "adder64", "").unwrap();

        assert_eq!(circ.input_len(), 128);
        assert_eq!(circ.output_len(), 64);
        assert_eq!(circ.xor_count(), 313);
        assert_eq!(circ.and_count(), 63);
    }

    #[test]
    fn test_aes_reverse() {
        let circ = Circuit::parse(
            "circuits/bristol/aes_128_reverse.txt",
            "aes_128_reverse",
            "",
        )
        .unwrap();

        assert_eq!(circ.input_len(), 256);
        assert_eq!(circ.output_len(), 128);
        assert_eq!(circ.xor_count(), 28176);
        assert_eq!(circ.and_count(), 6400);
    }
}
