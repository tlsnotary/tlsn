// Parses Bristol-fashion circuit and saves it in yaml format

use clap::Parser;
use mpc_circuits::{builder::CircuitBuilder, BitOrder, Circuit, CircuitSpec, WireGroup};
use serde_yaml::to_string;
use std::{
    fs::{read_dir, write},
    sync::Arc,
};

#[derive(Clone, Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(short)]
    name: String,
    #[clap(short)]
    version: String,
    /// This flag reverses the circuit input and output wires, ie flips the bit order
    /// of the circuit.
    ///
    /// Any byte values will also be reversed, ie flipping the endianness. Little-endian
    /// inputs/outputs will become big-endian and vice versa.
    #[clap(short, default_value = "false")]
    reverse: bool,
    /// Path to bristol fashion circuit
    src: String,
    /// Path to directory to save spec
    #[clap(default_value = "circuits/specs")]
    spec_dest: String,
}

fn main() {
    let args = Args::parse();
    let Ok(_) = read_dir(args.spec_dest.as_str()) else {
        panic!("Spec destination directory does not exist");
    };

    let src_path = args.src.as_str();

    let mut circ = Circuit::parse(src_path, &args.name, &args.version, BitOrder::Lsb0)
        .expect("Failed to parse");

    if args.reverse {
        circ = reverse_bristol(&circ);
    }

    let circ_spec = CircuitSpec::from(circ.as_ref());

    // Save spec
    write(
        format!("{}/{}.yml", args.spec_dest.as_str(), args.name),
        to_string(&circ_spec).expect("Failed to serialize yaml"),
    )
    .expect("Failed to save spec");

    println!("Successfully processed {}", &args.name);
}

// Reverses the input and output wires of a circuit.
fn reverse_bristol(circ: &Circuit) -> Arc<Circuit> {
    let id = circ.id().clone().to_string();
    let mut builder = CircuitBuilder::new(
        &id,
        circ.description(),
        circ.version(),
        match circ.bit_order() {
            BitOrder::Lsb0 => BitOrder::Msb0,
            BitOrder::Msb0 => BitOrder::Lsb0,
        },
    );

    let new_inputs = circ
        .inputs()
        .iter()
        .map(|input| {
            builder.add_input(
                input.id().as_ref(),
                input.description(),
                input.value_type(),
                input.len(),
            )
        })
        .collect::<Vec<_>>();

    let mut builder = builder.build_inputs();

    let original_circ = builder.add_circ(&circ);

    // For each input, create a new input with reversed wires.
    for (idx, input) in new_inputs.iter().enumerate() {
        let input_wires = input[..].iter().cloned().collect::<Vec<_>>();
        let original_input_wires = original_circ.input(idx).unwrap()[..]
            .iter()
            .cloned()
            .collect::<Vec<_>>();

        // Connect the new input wires to the original input wires in reverse order.
        for (feed, sink) in input_wires.iter().zip(original_input_wires.iter().rev()) {
            builder.connect(&[*feed], &[*sink]);
        }
    }

    let mut builder = builder.build_gates();

    let new_outputs = circ
        .outputs()
        .iter()
        .map(|output| {
            builder.add_output(
                output.id().as_ref(),
                output.description(),
                output.value_type(),
                output.len(),
            )
        })
        .collect::<Vec<_>>();

    // For each output, create a new output with reversed wires.
    for (idx, output) in new_outputs.iter().enumerate() {
        let output_wires = output[..].iter().cloned().collect::<Vec<_>>();
        let original_output_wires = original_circ.output(idx).unwrap()[..]
            .iter()
            .cloned()
            .collect::<Vec<_>>();

        // Connect the new output wires to the original output wires in reverse order.
        for (feed, sink) in original_output_wires.iter().zip(output_wires.iter().rev()) {
            builder.connect(&[*feed], &[*sink]);
        }
    }

    builder.build_circuit().expect("Failed to build circuit")
}
