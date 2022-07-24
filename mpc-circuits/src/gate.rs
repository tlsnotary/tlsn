/// Basic components of a circuit.
///
/// `id` represents the gate id.
/// `xref` and `yref` are the wire ids of the gate inputs
/// `zref` is the wire id of the gate output
#[derive(Clone, Debug, PartialEq)]
pub enum Gate {
    Xor {
        id: usize,
        xref: usize,
        yref: usize,
        zref: usize,
    },
    And {
        id: usize,
        xref: usize,
        yref: usize,
        zref: usize,
    },
    Inv {
        id: usize,
        xref: usize,
        zref: usize,
    },
}
