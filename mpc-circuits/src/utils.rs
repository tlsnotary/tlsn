use std::collections::HashMap;

use crate::Gate;

/// Sorts gates into topological order, so we can evaluate them sequentially.
pub(crate) fn topological_sort(gates: Vec<Gate>) -> Vec<Gate> {
    // Gate id -> Vec<Gate Id>
    let mut graph: HashMap<usize, Vec<usize>> = HashMap::new();
    // Sink id -> Vec<Gate id>
    let mut sinks: HashMap<usize, Vec<usize>> = HashMap::new();
    // Feed id -> Gate id
    let mut feeds: HashMap<usize, usize> = HashMap::new();

    for (gid, gate) in gates.iter().enumerate() {
        graph.insert(gid, vec![]);
        feeds.insert(gate.zref(), gid);
        if let Some(sink) = sinks.get_mut(&gate.xref()) {
            sink.push(gid);
        } else {
            sinks.insert(gate.xref(), vec![gid]);
        }
        if let Some(yref) = gate.yref() {
            if let Some(sink) = sinks.get_mut(&yref) {
                sink.push(gid);
            } else {
                sinks.insert(yref, vec![gid]);
            }
        }
    }

    for (feed, gid) in feeds {
        if let Some(s) = sinks.get(&feed) {
            graph.get_mut(&gid).unwrap().extend(s);
        }
    }

    fn recursion(
        gid: usize,
        graph: &HashMap<usize, Vec<usize>>,
        visited: &mut Vec<bool>,
        stack: &mut Vec<usize>,
    ) {
        visited[gid] = true;

        for adjacent_gid in graph.get(&gid).unwrap() {
            if !visited[*adjacent_gid] {
                recursion(*adjacent_gid, graph, visited, stack);
            }
        }

        stack.push(gid);
    }

    let mut visited = vec![false; gates.len()];
    let mut stack: Vec<usize> = vec![];
    for gid in 0..gates.len() {
        if !visited[gid] {
            recursion(gid, &graph, &mut visited, &mut stack);
        }
    }

    stack.into_iter().rev().map(|gid| gates[gid]).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{Circuit, WireGroup, ADDER_64};
    use rand::{seq::SliceRandom, thread_rng};

    #[test]
    fn test_topological_sort() {
        let mut circ = Circuit::load_bytes(ADDER_64).unwrap();

        // Randomly shuffle gates then resort them prior to evaluation
        for _ in 0..8 {
            circ.gates.shuffle(&mut thread_rng());

            circ.gates = topological_sort(circ.gates);

            circ.evaluate(&[
                circ.input(0).unwrap().to_value(0u64).unwrap(),
                circ.input(1).unwrap().to_value(0u64).unwrap(),
            ])
            .unwrap();
        }
    }
}
