use crate::predicates::Pred;
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "expr.pest"]
struct ExprParser;

fn parse_expr(input: &str) -> Result<Pred, pest::error::Error<Rule>> {
    let mut pairs = ExprParser::parse(Rule::expr, input)?;
    Ok(build_expr(pairs.next().unwrap()))
}

fn build_expr(pair: Pair<Rule>) -> Pred {
    match pair.as_rule() {
        Rule::expr | Rule::or_expr => build_left_assoc(pair.into_inner(), Rule::and_expr, Pred::Or),
        Rule::and_expr => build_left_assoc(pair.into_inner(), Rule::not_expr, Pred::And),
        Rule::not_expr => {
            // NOT* cmp
            let mut inner = pair.into_inner(); // possibly multiple NOT then a cmp
                                               // Count NOTs, then parse cmp
            let mut not_count = 0;
            let mut rest = Vec::new();
            for p in inner {
                match p.as_rule() {
                    Rule::NOT => not_count += 1,
                    _ => {
                        rest.push(p);
                    }
                }
            }
            let mut node = build_cmp(rest.into_iter().next().expect("cmp missing"));
            if not_count % 2 == 1 {
                node = Pred::Not(Box::new(node));
            }
            node
        }
        Rule::cmp => build_cmp(pair),
        Rule::primary => build_expr(pair.into_inner().next().unwrap()),
        Rule::paren => build_expr(pair.into_inner().next().unwrap()),
        _ => unreachable!("unexpected rule: {:?}", pair.as_rule()),
    }
}

fn build_left_assoc(
    mut inner: Pairs<Rule>,
    unit_rule: Rule,
    mk_node: impl Fn(Vec<Pred>) -> Pred,
) -> Pred {
    // pattern: unit (OP unit)*
    let mut nodes = Vec::new();
    // First unit
    if let Some(first) = inner.next() {
        assert_eq!(first.as_rule(), unit_rule);
        nodes.push(build_expr(first));
    }
    // Remaining are: OP unit pairs; we only collect the units and wrap later.
    while let Some(next) = inner.next() {
        // next is the operator token pair (AND/OR), skip it
        // then the unit:
        if let Some(unit) = inner.next() {
            assert_eq!(unit.as_rule(), unit_rule);
            nodes.push(build_expr(unit));
        }
    }
    if nodes.len() == 1 {
        nodes.pop().unwrap()
    } else {
        mk_node(nodes)
    }
}

fn build_cmp(pair: Pair<Rule>) -> Pred {
    // cmp: primary (cmp_op primary)?
    let mut inner = pair.into_inner();
    let lhs = inner.next().unwrap();
    let lhs_term = parse_term(lhs);
    if let Some(op_pair) = inner.next() {
        let op = match op_pair.as_str() {
            "==" => CmpOp::Eq,
            "!=" => CmpOp::Ne,
            "<" => CmpOp::Lt,
            "<=" => CmpOp::Lte,
            ">" => CmpOp::Gt,
            ">=" => CmpOp::Gte,
            _ => unreachable!(),
        };
        let rhs = parse_term(inner.next().unwrap());
        // Map to your Atom constraint form (LHS must be x[idx]):
        let (index, rhs_val) = match (lhs_term, rhs) {
            (Term::Idx(i), Term::Const(c)) => (i, Rhs::Const(c)),
            (Term::Idx(i1), Term::Idx(i2)) => (i1, Rhs::Idx(i2)),
            // If you want to allow const OP idx or const OP const, handle here (flip, etc.)
            other => panic!("unsupported comparison pattern: {:?}", other),
        };
        Pred::Atom(Atom {
            index,
            op,
            rhs: rhs_val,
        })
    } else {
        // A bare primary is treated as a boolean atom; you can decide policy.
        // Here we treat "x[i]" as (x[i] != 0) and const as (const != 0).
        match lhs_term {
            Term::Idx(i) => Pred::Atom(Atom {
                index: i,
                op: CmpOp::Ne,
                rhs: Rhs::Const(0),
            }),
            Term::Const(c) => {
                if c != 0 {
                    Pred::Or(vec![])
                } else {
                    Pred::And(vec![])
                } // true/false constants if you add Const
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum Term {
    Idx(usize),
    Const(u8),
}

fn parse_term(pair: Pair<Rule>) -> Term {
    match pair.as_rule() {
        Rule::atom => parse_term(pair.into_inner().next().unwrap()),
        Rule::byte_idx => {
            // "x" "[" number "]"
            let mut i = pair.into_inner();
            let num = i.find(|p| p.as_rule() == Rule::number).unwrap();
            Term::Idx(num.as_str().parse::<usize>().unwrap())
        }
        Rule::byte_const => {
            let n = pair.into_inner().next().unwrap(); // number
            Term::Const(n.as_str().parse::<u8>().unwrap())
        }
        Rule::paren => parse_term(pair.into_inner().next().unwrap()),
        Rule::primary => parse_term(pair.into_inner().next().unwrap()),
        _ => unreachable!("term {:?}", pair.as_rule()),
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_and() {
        let pred = parse_expr("x[100] < x[300] && x[200] == 2 || ! (x[5] >= 57)").unwrap();
        // `pred` is a Pred::Or with an And on the left and a Not on the right,
        // with Atoms inside.
    }
}
