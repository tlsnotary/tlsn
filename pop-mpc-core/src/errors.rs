use prost::DecodeError;
use regex;
use std::fmt::{self, Display, Formatter};

///////////////////////////////////////////////////////////////////////////////
/// CircuitEval

#[derive(Debug)]
pub enum CircuitEvalError {
    UninitializedValue(usize),
}

impl Display for CircuitEvalError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            CircuitEvalError::UninitializedValue(wire) => {
                write!(f, "Uninitialized value, wire {}", wire)
            }
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
            Self::IoError(e) => write!(f, "io error: {}", e),
            Self::RegexError(e) => write!(f, "regex error: {}", e),
            Self::ParseIntError => write!(f, "unable to parse integer"),
            Self::ParseLineError(s) => write!(f, "unable to parse line '{}'", s),
            Self::ParseGateError(s) => write!(f, "unable to parse gate '{}'", s),
            Self::InputError() => write!(f, "invalid circuit inputs"),
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
/// Circuit Load

/// Errors emitted by the circuit parser.
#[derive(Debug)]
pub enum CircuitLoadError {
    /// An I/O error occurred.
    IoError(std::io::Error),
    /// A decoding error occurred.
    DecodeError(DecodeError),
    /// Error occurred when mapping models
    MappingError,
}

impl Display for CircuitLoadError {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "io error: {}", e),
            Self::DecodeError(e) => write!(f, "decode error: {}", e),
            Self::MappingError => write!(f, "mapping error"),
        }
    }
}

impl From<std::io::Error> for CircuitLoadError {
    fn from(e: std::io::Error) -> Self {
        Self::IoError(e)
    }
}

impl From<DecodeError> for CircuitLoadError {
    fn from(e: DecodeError) -> Self {
        Self::DecodeError(e)
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
