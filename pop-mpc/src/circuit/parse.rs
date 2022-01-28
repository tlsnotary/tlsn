use super::Circuit;
use crate::errors::CircuitParserError;
use crate::gate::Gate;
use regex::{Captures, Regex};
use std::{
    fs::File,
    io::{BufRead, BufReader},
    str::FromStr,
};

/// Parses captures into a Vec for convenience
fn line2vec<'a>(re: &Regex, line: &'a str) -> Result<Vec<&'a str>, CircuitParserError> {
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
    /// https://homes.esat.kuleuven.be/~nsmart/MPC/
    pub fn parse(filename: &str) -> Result<Self, CircuitParserError> {
        let f = File::open(filename)?;
        let mut reader = BufReader::new(f);

        // Parse first line: ngates nwires\n
        let mut line = String::new();
        let _ = reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)")?;
        let line_1 = line2vec(&re, &line)?;

        // Check that first line has 2 values: ngates, nwires
        if line_1.len() != 2 {
            return Err(CircuitParserError::ParseLineError(line));
        }

        let ngates: usize = line_1[0].parse()?;
        let nwires: usize = line_1[1].parse()?;

        // Parse second line: ninputs input_0_nwires input_1_nwires...
        let mut line = String::new();
        let _ = reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s*")?;
        let line_2 = line2vec(&re, &line)?;

        let ninputs: usize = line_2[0].parse()?; // Number of circuit inputs
        let input_nwires: Vec<usize> = line_2[1..]
            .iter()
            .map(|nwires| {
                let nwires: usize = nwires.parse().unwrap();
                nwires
            })
            .collect();
        let ninput_wires: usize = input_nwires.iter().sum();

        // Check that nwires is specified for every input
        if input_nwires.len() != ninputs {
            return Err(CircuitParserError::ParseLineError(line));
        }

        // Parse third line: noutputs output_0_nwires output_1_nwires...
        let mut line = String::new();
        let _ = reader.read_line(&mut line)?;
        let re = Regex::new(r"(\d+)\s*")?;
        let line_3 = line2vec(&re, &line)?;

        let noutputs: usize = line_3[0].parse()?; // Number of circuit outputs
        let output_nwires: Vec<usize> = line_3[1..]
            .iter()
            .map(|nwires| {
                let nwires: usize = nwires.parse().unwrap();
                nwires
            })
            .collect();
        let noutput_wires: usize = output_nwires.iter().sum();

        // Check that nwires is specified for every output
        if output_nwires.len() != noutputs {
            return Err(CircuitParserError::ParseLineError(line));
        }

        let mut circ = Self::new(
            ngates,
            nwires,
            ninputs,
            input_nwires.clone(),
            ninput_wires,
            noutput_wires,
        );

        let re = Regex::new(r"(\d+|\S+)\s*")?;

        let mut id = 0;

        // Process gates
        for line in reader.lines() {
            let line = line?;
            if line.is_empty() {
                continue;
            }
            let gate_vals = line2vec(&re, &line)?;
            let typ = gate_vals.last().unwrap();
            let gate = match *typ {
                "INV" => {
                    let xref: usize = gate_vals[2].parse()?;
                    let zref: usize = gate_vals[3].parse()?;
                    Gate::Inv { id, xref, zref }
                }
                "AND" => {
                    let xref: usize = gate_vals[2].parse()?;
                    let yref: usize = gate_vals[3].parse()?;
                    let zref: usize = gate_vals[4].parse()?;
                    Gate::And {
                        id,
                        xref,
                        yref,
                        zref,
                    }
                }
                "XOR" => {
                    let xref: usize = gate_vals[2].parse()?;
                    let yref: usize = gate_vals[3].parse()?;
                    let zref: usize = gate_vals[4].parse()?;
                    Gate::Xor {
                        id,
                        xref,
                        yref,
                        zref,
                    }
                }
                _ => {
                    return Err(CircuitParserError::ParseGateError(line.to_string()));
                }
            };
            circ.gates.push(gate);
            id += 1;
        }
        if id != ngates {
            return Err(CircuitParserError::ParseGateError(format!(
                "expecting {ngates} gates, parsed {id}"
            )));
        }
        Ok(circ)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn test_parse_adder64() {
        let circ = Circuit::parse("circuits/adder64.txt").unwrap();

        assert_eq!(circ.ninput_wires, 128);
        assert_eq!(circ.noutput_wires, 64);

        let a = vec![0u8; 64];
        let b = vec![0u8; 64];
        let output = circ.eval(vec![a, b]).unwrap();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let mut a = vec![0u8; 64];
        a[63] = 1;
        a.reverse();
        let b = vec![0u8; 64];
        let mut output = circ.eval(vec![a, b]).unwrap();
        output.reverse();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        let a = vec![0u8; 64];
        let mut b = vec![0u8; 64];
        b[63] = 1;
        b.reverse();
        let mut output = circ.eval(vec![a, b]).unwrap();
        output.reverse();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        let mut a = vec![0u8; 64];
        a[63] = 1;
        a.reverse();
        let mut b = vec![0u8; 64];
        b[63] = 1;
        b.reverse();
        let mut output = circ.eval(vec![a, b]).unwrap();
        output.reverse();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000010"
        );

        let a = vec![1u8; 64];
        let mut b = vec![0u8; 64];
        b[63] = 1;
        b.reverse();
        let mut output = circ.eval(vec![a, b]).unwrap();
        output.reverse();
        assert_eq!(
            output.iter().map(|i| i.to_string()).collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_aes_reverse() {
        let circ = Circuit::parse("circuits/aes_128_reverse.txt").unwrap();

        assert_eq!(circ.ninput_wires, 256);
        assert_eq!(circ.noutput_wires, 128);

        let mut key = vec![0u8; 128];
        let mut pt = vec![0u8; 128];
        let mut output = circ.eval(vec![key, pt]).unwrap();
        output.reverse();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");

        key = vec![1u8; 128];
        pt = vec![0u8; 128];
        output = circ.eval(vec![key, pt]).unwrap();
        output.reverse();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");

        key = vec![0u8; 128];
        key[7] = 1;
        key.reverse();
        pt = vec![0u8; 128];
        output = circ.eval(vec![key, pt]).unwrap();
        output.reverse();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");

        key = vec![0u8; 128];
        for i in 0..8 {
            key[127 - i] = 1;
        }
        key.reverse();
        pt = vec![0u8; 128];
        output = circ.eval(vec![key, pt]).unwrap();
        output.reverse();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "11010101110010011000110001001000001001010101111101111000110011000100011111100001010010011110010101011100111111000011111111111101");

        key = vec![0u8; 128];
        for i in 0..8 {
            key[127 - i] = 1;
        }
        key.reverse();
        pt = vec![0u8; 128];
        pt.splice(
            ..64,
            [
                0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0,
                0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1,
                0, 1, 1, 0, 1, 1, 0, 1,
            ],
        );
        pt.reverse();
        output = circ.eval(vec![key, pt]).unwrap();
        output.reverse();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                    "10001010010011010111111100000011011000110101001101101001101011100001101111001110101010001010101010000000100010000001000101010111");

        key = vec![0u8; 128];

        for i in 0..8 {
            key[i] = 1;
        }

        key.reverse();
        pt = vec![0u8; 128];
        output = circ.eval(vec![key, pt]).unwrap();
        output.reverse();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                    "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101");
    }

    #[test]
    fn test_aes_old() {
        let circ = Circuit::parse("circuits/aes_128.txt").unwrap();

        assert_eq!(circ.ninput_wires, 256);
        assert_eq!(circ.noutput_wires, 128);

        let mut key = vec![0u8; 128];
        let mut pt = vec![0u8; 128];
        let mut output = circ.eval(vec![pt, key]).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");

        key = vec![1u8; 128];
        pt = vec![0u8; 128];
        output = circ.eval(vec![pt, key]).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");

        key = vec![0u8; 128];
        key[7] = 1;

        pt = vec![0u8; 128];
        output = circ.eval(vec![pt, key]).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");

        key = vec![0u8; 128];
        for i in 0..8 {
            key[127 - i] = 1;
        }

        pt = vec![0u8; 128];
        output = circ.eval(vec![pt, key]).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                   "11010101110010011000110001001000001001010101111101111000110011000100011111100001010010011110010101011100111111000011111111111101");

        key = vec![0u8; 128];
        for i in 0..8 {
            key[127 - i] = 1;
        }
        pt = vec![0u8; 128];
        pt.splice(
            ..64,
            [
                0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 0,
                0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 1,
                0, 1, 1, 0, 1, 1, 0, 1,
            ],
        );
        output = circ.eval(vec![pt, key]).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                    "10001010010011010111111100000011011000110101001101101001101011100001101111001110101010001010101010000000100010000001000101010111");

        key = vec![0u8; 128];

        for i in 0..8 {
            key[i] = 1;
        }

        pt = vec![0u8; 128];
        output = circ.eval(vec![pt, key]).unwrap();
        assert_eq!(output.iter().map(|i| i.to_string()).collect::<String>(),
                    "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101");
    }
}
