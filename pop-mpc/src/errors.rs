use regex;
use std::fmt::{self, Display, Formatter};

/// Errors that may occur when using the `GateOps` trait.
#[derive(Debug)]
pub enum GateOpsError {
    /// Operation not implemented
    OperationNotImplemented,
}

impl Display for GateOpsError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            GateOpsError::OperationNotImplemented => "operation not implemented".fmt(f),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// CircuitEval

#[derive(Debug)]
pub enum CircuitEvalError {
    UninitializedValue(usize),
    GateOpsError(GateOpsError),
}

impl From<GateOpsError> for CircuitEvalError {
    fn from(error: GateOpsError) -> Self {
        CircuitEvalError::GateOpsError(error)
    }
}

impl Display for CircuitEvalError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CircuitEvalError::UninitializedValue(wire) => {
                write!(f, "Uninitialized value, wire {}", wire)
            }
            CircuitEvalError::GateOpsError(err) => write!(f, "Gate operation error: {:?}", err),
        }
    }
}

///////////////////////////////////////////////////////////////////////////////
/// Circuit Parser

/// Errors emitted by the circuit parser.
#[derive(Debug)]
pub enum CircuitParserError {
    /// An I/O error occurred.
    IoError(std::io::Error),
    /// A regular expression parsing error occurred.
    RegexError(regex::Error),
    /// An error occurred parsing an integer.
    ParseIntError,
    /// An error occurred parsing a line.
    ParseLineError(String),
    /// An error occurred parsing a gate type.
    ParseGateError(String),
    /// An error occurred due to invalid garbler/evaluator inputs.
    InputError(),
}

impl Display for CircuitParserError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CircuitParserError::IoError(e) => write!(f, "io error: {}", e),
            CircuitParserError::RegexError(e) => write!(f, "regex error: {}", e),
            CircuitParserError::ParseIntError => write!(f, "unable to parse integer"),
            CircuitParserError::ParseLineError(s) => write!(f, "unable to parse line '{}'", s),
            CircuitParserError::ParseGateError(s) => write!(f, "unable to parse gate '{}'", s),
            CircuitParserError::InputError() => write!(f, "invalid circuit inputs"),
        }
    }
}

impl From<std::io::Error> for CircuitParserError {
    fn from(e: std::io::Error) -> CircuitParserError {
        CircuitParserError::IoError(e)
    }
}

impl From<regex::Error> for CircuitParserError {
    fn from(e: regex::Error) -> CircuitParserError {
        CircuitParserError::RegexError(e)
    }
}

impl From<std::num::ParseIntError> for CircuitParserError {
    fn from(_: std::num::ParseIntError) -> CircuitParserError {
        CircuitParserError::ParseIntError
    }
}

///////////////////////////////////////////////////////////////////////////////
/// Circuit Garbling

#[derive(Debug)]
pub enum GeneratorError {
    UninitializedLabel(usize),
}

impl Display for GeneratorError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            GeneratorError::UninitializedLabel(wire) => {
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
            EvaluatorError::UninitializedLabel(wire) => {
                write!(f, "Uninitialized label, wire {}", wire)
            }
            EvaluatorError::InvalidInputCount(n, expected) => {
                write!(f, "Invalid input count {} expected {}", n, expected)
            }
        }
    }
}
