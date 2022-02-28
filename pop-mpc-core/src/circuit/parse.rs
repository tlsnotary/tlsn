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
    /// `https://homes.esat.kuleuven.be/~nsmart/MPC/`
    pub fn parse(filename: &str, name: &str, version: &str) -> Result<Self, CircuitParserError> {
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
            name.to_string(),
            version.to_string(),
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
                    circ.nand += 1;
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
                    circ.nxor += 1;
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
    use crate::circuit::CircuitInput;
    use std::time::{Duration, Instant};

    #[test]
    fn test_parse_adder64() {
        let circ = Circuit::parse("circuits/adder64.txt", "adder64", "").unwrap();

        assert_eq!(circ.ninput_wires, 128);
        assert_eq!(circ.noutput_wires, 64);
        assert_eq!(circ.nxor, 313);
        assert_eq!(circ.nand, 63);

        let a = vec![false; 64];
        let b = vec![false; 64];
        let inputs = [a, b].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let output = circ.eval(inputs).unwrap();
        assert_eq!(
            output
                .into_iter()
                .map(|i| (i as u8).to_string())
                .collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        let mut a = vec![false; 64];
        a[63] = true;
        a.reverse();
        let b = vec![false; 64];
        let inputs = [a, b].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(
            output
                .into_iter()
                .map(|i| (i as u8).to_string())
                .collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        let a = vec![false; 64];
        let mut b = vec![false; 64];
        b[63] = true;
        b.reverse();
        let inputs = [a, b].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(
            output
                .into_iter()
                .map(|i| (i as u8).to_string())
                .collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000001"
        );

        let mut a = vec![false; 64];
        a[63] = true;
        a.reverse();
        let mut b = vec![false; 64];
        b[63] = true;
        b.reverse();
        let inputs = [a, b].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(
            output
                .into_iter()
                .map(|i| (i as u8).to_string())
                .collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000010"
        );

        let a = vec![true; 64];
        let mut b = vec![false; 64];
        b[63] = true;
        b.reverse();
        let inputs = [a, b].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(
            output
                .into_iter()
                .map(|i| (i as u8).to_string())
                .collect::<String>(),
            "0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_aes_reverse() {
        let circ = Circuit::parse("circuits/aes_128_reverse.txt", "aes_128_reverse", "").unwrap();

        assert_eq!(circ.ninput_wires, 256);
        assert_eq!(circ.noutput_wires, 128);
        assert_eq!(circ.nxor, 28176);
        assert_eq!(circ.nand, 6400);

        let mut key = vec![false; 128];
        let mut pt = vec![false; 128];
        let inputs = [key, pt].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");

        key = vec![true; 128];
        pt = vec![false; 128];
        let inputs = [key, pt].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");

        key = vec![false; 128];
        key[7] = true;
        key.reverse();
        pt = vec![false; 128];
        let inputs = [key, pt].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");

        key = vec![false; 128];
        for i in 0..8 {
            key[127 - i] = true;
        }
        key.reverse();
        pt = vec![false; 128];
        let inputs = [key, pt].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "11010101110010011000110001001000001001010101111101111000110011000100011111100001010010011110010101011100111111000011111111111101");

        key = vec![false; 128];

        for i in 0..8 {
            key[i] = true;
        }

        key.reverse();
        pt = vec![false; 128];
        let inputs = [key, pt].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        output.reverse();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                    "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101");
    }

    #[test]
    fn test_aes_old() {
        let circ = Circuit::parse("circuits/aes_128.txt", "aes_128", "").unwrap();

        assert_eq!(circ.ninput_wires, 256);
        assert_eq!(circ.noutput_wires, 128);
        assert_eq!(circ.nxor, 25124);
        assert_eq!(circ.nand, 6800);

        let mut key = vec![false; 128];
        let mut pt = vec![false; 128];
        let inputs = [pt, key].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        let mut output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "01100110111010010100101111010100111011111000101000101100001110111000100001001100111110100101100111001010001101000010101100101110");

        key = vec![true; 128];
        pt = vec![false; 128];
        let inputs = [pt, key].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "10100001111101100010010110001100100001110111110101011111110011011000100101100100010010000100010100111000101111111100100100101100");

        key = vec![false; 128];
        key[7] = true;

        pt = vec![false; 128];
        let inputs = [pt, key].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "11011100000011101101100001011101111110010110000100011010101110110111001001001001110011011101000101101000110001010100011001111110");

        key = vec![false; 128];
        for i in 0..8 {
            key[127 - i] = true;
        }

        pt = vec![false; 128];
        let inputs = [pt, key].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                   "11010101110010011000110001001000001001010101111101111000110011000100011111100001010010011110010101011100111111000011111111111101");

        key = vec![false; 128];

        for i in 0..8 {
            key[i] = true;
        }

        pt = vec![false; 128];
        let inputs = [pt, key].concat();
        let inputs = inputs
            .into_iter()
            .enumerate()
            .map(|(id, value)| CircuitInput { id, value })
            .collect();
        output = circ.eval(inputs).unwrap();
        assert_eq!(output.into_iter().map(|i| (i as u8).to_string()).collect::<String>(),
                    "10110001110101110101100000100101011010110010100011111101100001010000101011010100100101000100001000001000110011110001000101010101");
    }
}
