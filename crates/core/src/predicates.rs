//! Predicate and compiler.

use std::{collections::HashMap, fmt};

use mpz_circuits::{itybity::ToBits, ops, Circuit, CircuitBuilder, Feed, Node};
use rangeset::RangeSet;

/// ddd
#[derive(Debug, Clone)]
pub(crate) enum Pred {
    And(Vec<Pred>),
    Or(Vec<Pred>),
    Not(Box<Pred>),
    Atom(Atom),
    // An always-true predicate.
    True,
    // An always-false predicate.
    False,
}

impl Pred {
    /// Returns sorted unique byte indices of this predicate.
    pub(crate) fn indices(&self) -> Vec<usize> {
        let mut indices = self.indices_internal(self);
        indices.sort_unstable();
        indices.dedup();
        indices
    }

    // Returns the number of leaves (i.e atoms) the AST of this predicate has.
    pub(crate) fn leaves(&self) -> usize {
        match self {
            Pred::And(vec) => vec.iter().map(|p| p.leaves()).sum(),
            Pred::Or(vec) => vec.iter().map(|p| p.leaves()).sum(),
            Pred::Not(p) => p.leaves(),
            Pred::Atom(atom) => 1,
            Pred::True => 0,
            Pred::False => 0,
        }
    }

    /// Returns all byte indices of the given `pred`icate.
    fn indices_internal(&self, pred: &Pred) -> Vec<usize> {
        match pred {
            Pred::And(vec) => vec
                .iter()
                .flat_map(|p| self.indices_internal(p))
                .collect::<Vec<_>>(),
            Pred::Or(vec) => vec
                .iter()
                .flat_map(|p| self.indices_internal(p))
                .collect::<Vec<_>>(),
            Pred::Not(p) => self.indices_internal(p),
            Pred::Atom(atom) => {
                let mut indices = Vec::new();
                indices.push(atom.index);
                if let Rhs::Idx(idx) = atom.rhs {
                    indices.push(idx);
                }
                indices
            }
            Pred::True => vec![],
            Pred::False => vec![],
        }
    }
}

impl fmt::Display for Pred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_with_indent(f, 0)
    }
}

impl Pred {
    fn fmt_with_indent(&self, f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
        // helper to write the current indentation
        fn pad(f: &mut fmt::Formatter<'_>, indent: usize) -> fmt::Result {
            // 2 spaces per level; tweak as you like
            write!(f, "{:indent$}", "", indent = indent * 2)
        }

        match self {
            Pred::And(preds) => {
                pad(f, indent)?;
                writeln!(f, "And(")?;
                for p in preds {
                    p.fmt_with_indent(f, indent + 1)?;
                }
                pad(f, indent)?;
                writeln!(f, ")")
            }
            Pred::Or(preds) => {
                pad(f, indent)?;
                writeln!(f, "Or(")?;
                for p in preds {
                    p.fmt_with_indent(f, indent + 1)?;
                }
                pad(f, indent)?;
                writeln!(f, ")")
            }
            Pred::Not(p) => {
                pad(f, indent)?;
                writeln!(f, "Not(")?;
                p.fmt_with_indent(f, indent + 1)?;
                pad(f, indent)?;
                writeln!(f, ")")
            }
            Pred::Atom(a) => {
                pad(f, indent)?;
                writeln!(f, "Atom({:?})", a)
            }
            Pred::True => {
                pad(f, indent)?;
                writeln!(f, "True")
            }
            Pred::False => {
                pad(f, indent)?;
                writeln!(f, "False")
            }
        }
    }
}

/// Atomic predicate of the form:
///   x[index] (op) rhs
#[derive(Debug, Clone)]
pub struct Atom {
    /// Left-hand side byte index `i` (x_i).
    pub index: usize,
    /// Comparison operator.
    pub op: CmpOp,
    /// Right-hand side operand (constant or x_j).
    pub rhs: Rhs,
}

/// ddd
#[derive(Debug, Clone)]
pub(crate) enum CmpOp {
    Eq,  // ==
    Ne,  // !=
    Gt,  // >
    Gte, // >=
    Lt,  // <
    Lte, // <=
}

/// RHS of a comparison
#[derive(Debug, Clone)]
pub enum Rhs {
    /// Byte at index
    Idx(usize),
    /// Literal constant.
    Const(u8),
}

/// Compiles a predicate into a circuit.
pub struct Compiler {
    /// A <byte index, circuit feeds> map.
    map: HashMap<usize, [Node<Feed>; 8]>,
}

impl Compiler {
    pub(crate) fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Compiles the given predicate into a circuit, consuming the
    /// compiler.
    pub(crate) fn compile(&mut self, pred: &Pred) -> Circuit {
        let mut builder = CircuitBuilder::new();

        for idx in pred.indices() {
            let feeds = (0..8).map(|_| builder.add_input()).collect::<Vec<_>>();
            self.map.insert(idx, feeds.try_into().unwrap());
        }

        let out = self.process(&mut builder, pred);

        builder.add_output(out);
        builder.build().unwrap()
    }

    // Processes a single predicate.
    fn process(&mut self, builder: &mut CircuitBuilder, pred: &Pred) -> Node<Feed> {
        match pred {
            Pred::And(vec) => {
                let out = vec
                    .iter()
                    .map(|p| self.process(builder, p))
                    .collect::<Vec<_>>();

                ops::all(builder, &out)
            }
            Pred::Or(vec) => {
                let out = vec
                    .iter()
                    .map(|p| self.process(builder, p))
                    .collect::<Vec<_>>();

                ops::any(builder, &out)
            }
            Pred::Not(p) => {
                let pred_out = self.process(builder, p);
                let inv = ops::inv(builder, [pred_out]);
                inv[0]
            }
            Pred::Atom(atom) => {
                let lhs = self.map.get(&atom.index).unwrap().clone();
                let rhs = match atom.rhs {
                    Rhs::Const(c) => const_feeds(builder, c),
                    Rhs::Idx(s) => self.map.get(&s).unwrap().clone(),
                };
                match atom.op {
                    CmpOp::Eq => ops::eq(builder, lhs, rhs),
                    CmpOp::Ne => ops::neq(builder, lhs, rhs),
                    CmpOp::Lt => ops::lt(builder, lhs, rhs),
                    CmpOp::Lte => ops::lte(builder, lhs, rhs),
                    CmpOp::Gt => ops::gt(builder, lhs, rhs),
                    CmpOp::Gte => ops::gte(builder, lhs, rhs),
                }
            }
            Pred::True => builder.get_const_one(),
            Pred::False => builder.get_const_zero(),
        }
    }
}

// Returns circuit feeds for the given constant u8 value.
fn const_feeds(builder: &CircuitBuilder, cnst: u8) -> [Node<Feed>; 8] {
    cnst.iter_lsb0()
        .map(|b| {
            if b {
                builder.get_const_one()
            } else {
                builder.get_const_zero()
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .expect("u8 has 8 feeds")
}

// Evaluates the predicate on the input `data`.
pub(crate) fn eval_pred(pred: &Pred, data: &[u8]) -> bool {
    match pred {
        Pred::And(vec) => vec.iter().map(|p| eval_pred(p, data)).all(|b| b),
        Pred::Or(vec) => vec.iter().map(|p| eval_pred(p, data)).any(|b| b),
        Pred::Not(p) => !eval_pred(p, data),
        Pred::Atom(atom) => {
            let lhs = data[atom.index];
            let rhs = match atom.rhs {
                Rhs::Const(c) => c,
                Rhs::Idx(s) => data[s],
            };
            match atom.op {
                CmpOp::Eq => lhs == rhs,
                CmpOp::Ne => lhs != rhs,
                CmpOp::Lt => lhs < rhs,
                CmpOp::Lte => lhs <= rhs,
                CmpOp::Gt => lhs > rhs,
                CmpOp::Gte => lhs >= rhs,
            }
        }
        Pred::True => true,
        Pred::False => true,
    }
}

/// Builds a predicate that an ascii integer is contained in the ranges.
fn is_ascii_integer(range: RangeSet<usize>) -> Pred {
    let mut preds = Vec::new();
    for idx in range.iter() {
        let lte = Pred::Atom(Atom {
            index: idx,
            op: CmpOp::Lte,
            rhs: Rhs::Const(57u8),
        });
        let gte = Pred::Atom(Atom {
            index: idx,
            op: CmpOp::Gte,
            rhs: Rhs::Const(48u8),
        });
        preds.push(Pred::And(vec![lte, gte]));
    }
    Pred::And(preds)
}

/// Builds a predicate that a valid HTTP header value is contained in the
/// ranges.
fn is_valid_http_header_value(range: RangeSet<usize>) -> Pred {
    let mut preds = Vec::new();
    for idx in range.iter() {
        let ne = Pred::Atom(Atom {
            index: idx,
            op: CmpOp::Ne,
            // ascii code for carriage return \r
            rhs: Rhs::Const(13u8),
        });
        preds.push(ne);
    }
    Pred::And(preds)
}

/// Builds a predicate that a valid JSON string is contained in the
/// ranges.
fn is_valid_json_string(range: RangeSet<usize>) -> Pred {
    assert!(
        range.len_ranges() == 1,
        "only a contiguous range is allowed"
    );

    const BACKSLASH: u8 = 92;

    // check if all unicode chars are allowed
    let mut preds = Vec::new();

    // Find all /u sequences
    for (i, idx) in range.iter().enumerate() {
        if i == range.len() - 1 {
            // if this is a last char, skip it
            continue;
        }
        let is_backslash = Pred::Atom(Atom {
            index: idx,
            op: CmpOp::Eq,
            rhs: Rhs::Const(BACKSLASH),
        });
    }
    Pred::And(preds)
}

// Returns a predicate that a unicode char is contained in the range
pub(crate) fn is_unicode(range: RangeSet<usize>) -> Pred {
    assert!(range.len() <= 4);
    match range.len() {
        1 => is_1_byte_unicode(range.max().unwrap()),
        2 => is_2_byte_unicode(range),
        3 => is_3_byte_unicode(range),
        4 => is_4_byte_unicode(range),
        _ => unimplemented!(),
    }
}

fn is_1_byte_unicode(pos: usize) -> Pred {
    Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Lte,
        rhs: Rhs::Const(127u8),
    })
}

fn is_2_byte_unicode(range: RangeSet<usize>) -> Pred {
    assert!(range.len() == 2);
    let mut iter = range.iter();

    // should be 110xxxxx
    let first = iter.next().unwrap();
    let gte = Pred::Atom(Atom {
        index: first,
        op: CmpOp::Gte,
        rhs: Rhs::Const(0xC0),
    });
    let lte = Pred::Atom(Atom {
        index: first,
        op: CmpOp::Lte,
        rhs: Rhs::Const(0xDF),
    });

    let second = iter.next().unwrap();
    Pred::And(vec![lte, gte, is_unicode_continuation(second)])
}

fn is_3_byte_unicode(range: RangeSet<usize>) -> Pred {
    assert!(range.len() == 3);
    let mut iter = range.iter();

    let first = iter.next().unwrap();
    // should be 1110xxxx
    let gte = Pred::Atom(Atom {
        index: first,
        op: CmpOp::Gte,
        rhs: Rhs::Const(0xE0),
    });
    let lte = Pred::Atom(Atom {
        index: first,
        op: CmpOp::Lte,
        rhs: Rhs::Const(0xEF),
    });

    let second = iter.next().unwrap();
    let third = iter.next().unwrap();

    Pred::And(vec![
        lte,
        gte,
        is_unicode_continuation(second),
        is_unicode_continuation(third),
    ])
}

fn is_4_byte_unicode(range: RangeSet<usize>) -> Pred {
    assert!(range.len() == 4);
    let mut iter = range.iter();

    let first = iter.next().unwrap();
    // should be 11110xxx
    let gte = Pred::Atom(Atom {
        index: first,
        op: CmpOp::Gte,
        rhs: Rhs::Const(0xF0),
    });
    let lte = Pred::Atom(Atom {
        index: first,
        op: CmpOp::Lte,
        rhs: Rhs::Const(0xF7),
    });

    let second = iter.next().unwrap();
    let third = iter.next().unwrap();
    let fourth = iter.next().unwrap();

    Pred::And(vec![
        lte,
        gte,
        is_unicode_continuation(second),
        is_unicode_continuation(third),
        is_unicode_continuation(fourth),
    ])
}

fn is_unicode_continuation(pos: usize) -> Pred {
    // should be 10xxxxxx
    let gte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Gte,
        rhs: Rhs::Const(0x80),
    });
    let lte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Lte,
        rhs: Rhs::Const(0xBF),
    });
    Pred::And(vec![lte, gte])
}

fn is_ascii_hex_digit(pos: usize) -> Pred {
    let gte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Gte,
        rhs: Rhs::Const(48u8),
    });
    let lte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Lte,
        rhs: Rhs::Const(57u8),
    });
    let is_digit = Pred::And(vec![lte, gte]);
    let gte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Gte,
        rhs: Rhs::Const(65u8),
    });
    let lte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Lte,
        rhs: Rhs::Const(70u8),
    });
    let is_upper = Pred::And(vec![lte, gte]);
    let gte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Gte,
        rhs: Rhs::Const(97u8),
    });
    let lte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Lte,
        rhs: Rhs::Const(102u8),
    });
    let is_lower = Pred::And(vec![lte, gte]);
    Pred::Or(vec![is_digit, is_lower, is_upper])
}

fn is_ascii_lowercase(pos: usize) -> Pred {
    let gte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Gte,
        rhs: Rhs::Const(48u8),
    });
    let lte = Pred::Atom(Atom {
        index: pos,
        op: CmpOp::Lte,
        rhs: Rhs::Const(57u8),
    });
    Pred::And(vec![lte, gte])
}

#[cfg(test)]
mod test {
    use super::*;
    use mpz_circuits::evaluate;
    use rand::rng;

    #[test]
    fn test_and() {
        let pred = Pred::And(vec![
            Pred::Atom(Atom {
                index: 100,
                op: CmpOp::Lt,
                rhs: Rhs::Idx(300),
            }),
            Pred::Atom(Atom {
                index: 200,
                op: CmpOp::Eq,
                rhs: Rhs::Const(2u8),
            }),
        ]);

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [1u8, 2, 3]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [1u8, 3, 3]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_or() {
        let pred = Pred::Or(vec![
            Pred::Atom(Atom {
                index: 100,
                op: CmpOp::Lt,
                rhs: Rhs::Idx(300),
            }),
            Pred::Atom(Atom {
                index: 200,
                op: CmpOp::Eq,
                rhs: Rhs::Const(2u8),
            }),
        ]);

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [1u8, 0, 3]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [1u8, 3, 0]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_not() {
        let pred = Pred::Not(Box::new(Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Lt,
            rhs: Rhs::Idx(300),
        })));

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [5u8, 3]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [1u8, 3]).unwrap();
        assert_eq!(out, false);
    }

    // Tests when RHS is a const.
    #[test]
    fn test_rhs_const() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Lt,
            rhs: Rhs::Const(22u8),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, 5u8).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, 23u8).unwrap();
        assert_eq!(out, false);
    }

    // Tests when RHS is an index.
    #[test]
    fn test_rhs_idx() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Lt,
            rhs: Rhs::Idx(200),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, 5u8, 10u8).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, 23u8, 5u8).unwrap();
        assert_eq!(out, false);
    }

    // Tests when same index is used in the predicate.
    #[test]
    fn test_same_idx() {
        let pred1 = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Eq,
            rhs: Rhs::Idx(100),
        });

        let pred2 = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Lt,
            rhs: Rhs::Idx(100),
        });

        let circ = Compiler::new().compile(&pred1);
        let out: bool = evaluate!(circ, 5u8).unwrap();
        assert_eq!(out, true);

        let circ = Compiler::new().compile(&pred2);
        let out: bool = evaluate!(circ, 5u8).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_atom_eq() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Eq,
            rhs: Rhs::Idx(300),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [5u8, 5]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [1u8, 3]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_atom_neq() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Ne,
            rhs: Rhs::Idx(300),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [5u8, 6]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [1u8, 1]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_atom_gt() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Gt,
            rhs: Rhs::Idx(300),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [7u8, 6]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [1u8, 1]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_atom_gte() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Gte,
            rhs: Rhs::Idx(300),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [7u8, 7]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [0u8, 1]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_atom_lt() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Lt,
            rhs: Rhs::Idx(300),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [2u8, 7]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [4u8, 1]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_atom_lte() {
        let pred = Pred::Atom(Atom {
            index: 100,
            op: CmpOp::Lte,
            rhs: Rhs::Idx(300),
        });

        let circ = Compiler::new().compile(&pred);
        let out: bool = evaluate!(circ, [2u8, 2]).unwrap();
        assert_eq!(out, true);

        let out: bool = evaluate!(circ, [4u8, 1]).unwrap();
        assert_eq!(out, false);
    }

    #[test]
    fn test_is_ascii_integer() {
        let text = "text with integers 123456 text";
        let pos = text.find("123456").unwrap();

        let pred = is_ascii_integer(RangeSet::from(pos..pos + 6));
        let bytes: &[u8] = text.as_bytes();

        let out = eval_pred(&pred, bytes);
        assert_eq!(out, true);

        let out = eval_pred(&pred, &[&[0u8], bytes].concat());
        assert_eq!(out, false);
    }

    #[test]
    fn test_is_valid_http_header_value() {
        let valid = "valid header value";
        let invalid = "invalid header \r value";

        let pred = is_valid_http_header_value(RangeSet::from(0..valid.len()));
        let out: bool = eval_pred(&pred, valid.as_bytes());
        assert_eq!(out, true);

        let pred = is_valid_http_header_value(RangeSet::from(0..invalid.len()));
        let out = eval_pred(&pred, invalid.as_bytes());
        assert_eq!(out, false);
    }

    #[test]
    fn test_is_unicode() {
        use rand::{distr::Alphanumeric, rng, Rng};
        let mut rng = rng();

        for _ in 0..1000000 {
            let mut s = String::from("HelloWorld");
            let insert_pos = 5; // logical character index (after "Hello")

            let byte_index = s
                .char_indices()
                .nth(insert_pos)
                .map(|(i, _)| i)
                .unwrap_or_else(|| s.len());
            // Pick a random Unicode scalar value (0x0000..=0x10FFFF)
            // Retry if it's in the surrogate range (U+D800..=U+DFFF)
            let c = loop {
                let code = rng.random_range(0x0000u32..=0x10FFFF);
                if !(0xD800..=0xDFFF).contains(&code) {
                    if let Some(ch) = char::from_u32(code) {
                        break ch;
                    }
                }
            };
            let mut buf = [0u8; 4]; // max UTF-8 length
            let encoded = c.encode_utf8(&mut buf); // returns &str
            let len = encoded.len();

            s.insert_str(byte_index, &c.to_string());

            let pred = is_unicode(RangeSet::from(byte_index..byte_index + len));
            let out = eval_pred(&pred, s.as_bytes());
            assert_eq!(out, true);
        }

        let bad_unicode = 255u8;
        let pred = is_unicode(RangeSet::from(0..1));
        let out = eval_pred(&pred, &[bad_unicode]);
        assert_eq!(out, false);
    }
}
