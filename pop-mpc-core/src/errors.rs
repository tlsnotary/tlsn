use std::fmt::{self, Display, Formatter};

///////////////////////////////////////////////////////////////////////////////
/// Circuit Garbling

#[derive(Debug)]
pub enum GeneratorError {
    UninitializedLabel(usize),
}

impl Display for GeneratorError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::UninitializedLabel(wire) => {
                write!(f, "Uninitialized label, wire {}", wire)
            }
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// Circuit Evaluating

#[derive(Debug)]
pub enum EvaluatorError {
    UninitializedLabel(usize),
    InvalidInputCount(usize, usize),
}

impl Display for EvaluatorError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::UninitializedLabel(wire) => {
                write!(f, "Uninitialized label, wire {}", wire)
            }
            Self::InvalidInputCount(n, expected) => {
                write!(f, "Invalid input count {} expected {}", n, expected)
            }
        }
    }
}
