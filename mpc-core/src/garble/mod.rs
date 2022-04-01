pub mod circuit;
pub mod errors;
pub mod evaluator;
pub mod generator;

#[derive(Debug, Clone)]
pub enum GarbleMessage {
    GarbledCircuit(circuit::GarbledCircuit),
}
