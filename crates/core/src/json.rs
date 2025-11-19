//!
use crate::predicates::Pred;
use pest::{
    iterators::{Pair, Pairs},
    Parser,
};
use pest_derive::Parser;
use pest_meta::{ast, parser as meta, parser::consume_rules, validator};

#[cfg(test)]
mod test {
    use core::panic;
    use std::cmp::{max, min};

    use crate::{
        config::prove::ProveConfig,
        predicates::{eval_pred, is_unicode, Atom, CmpOp, Compiler, Rhs},
    };

    use super::*;
    use mpz_circuits::{
        evaluate,
        ops::{all, any},
    };
    use pest_meta::ast::Expr;
    use rangeset::RangeSet;

    const MAX_LEN: usize = 999_999;

    #[derive(Debug, Clone)]
    enum Ex {
        RepEx(Rep),
        RepExactEx(RepExact),
        SeqEx(Seq),
        StrEx(Str),
        ChoiceEx(Choice),
        NegPredEx(NegPred),
        OptEx(Opt),
        // An expression which must be replaced with a copy of the rule.
        NestedEx,
        #[allow(non_camel_case_types)]
        ASCII_NONZERO_DIGIT,
        #[allow(non_camel_case_types)]
        ASCII_DIGIT,
        #[allow(non_camel_case_types)]
        // A single Unicode character
        ANY,
        #[allow(non_camel_case_types)]
        ASCII_HEX_DIGIT,
    }

    impl Ex {
        fn min_len(&self) -> usize {
            match self {
                Ex::RepEx(e) => 0,
                Ex::RepExactEx(e) => e.0 .0.min_len() * e.0 .1 as usize,
                Ex::StrEx(e) => e.0.len(),
                Ex::SeqEx(e) => e.0.min_len() + e.1.min_len(),
                Ex::ChoiceEx(e) => min(e.0.min_len(), e.1.min_len()),
                Ex::NegPredEx(e) => 0,
                Ex::ASCII_NONZERO_DIGIT => 1,
                Ex::ASCII_DIGIT => 1,
                Ex::ANY => 1,
                Ex::ASCII_HEX_DIGIT => 1,
                Ex::OptEx(e) => 0,
                Ex::NestedEx => 0,
                _ => unimplemented!(),
            }
        }

        fn max_len(&self) -> usize {
            match self {
                Ex::RepEx(e) => MAX_LEN,
                Ex::RepExactEx(e) => e.0 .0.max_len() * e.0 .1 as usize,
                Ex::StrEx(e) => e.0.len(),
                Ex::SeqEx(e) => e.0.max_len() + e.1.max_len(),
                Ex::ChoiceEx(e) => max(e.0.max_len(), e.1.max_len()),
                Ex::NegPredEx(e) => 0,
                Ex::ASCII_NONZERO_DIGIT => 1,
                Ex::ASCII_DIGIT => 1,
                Ex::ANY => 4,
                Ex::ASCII_HEX_DIGIT => 1,
                Ex::OptEx(e) => e.0.max_len(),
                Ex::NestedEx => 0,
                _ => unimplemented!(),
            }
        }
    }

    #[derive(Debug, Clone)]
    struct Rep(Box<Ex>);
    #[derive(Debug, Clone)]
    struct RepExact((Box<Ex>, u32));
    #[derive(Debug, Clone)]
    struct Str(String);
    #[derive(Debug, Clone)]
    struct Seq(Box<Ex>, Box<Ex>);
    #[derive(Debug, Clone)]
    struct Choice(Box<Ex>, Box<Ex>);
    #[derive(Debug, Clone)]
    struct NegPred(Box<Ex>);
    #[derive(Debug, Clone)]
    struct Opt(Box<Ex>);

    struct Rule {
        name: String,
        pub ex: Ex,
    }

    /// Builds the rules, returning the final expression.
    fn build_rules(ast_rules: &[ast::Rule]) -> Ex {
        let mut rules = Vec::new();
        // build from the bottom up
        let iter = ast_rules.iter().rev();
        for r in iter {
            println!("building rule with name {:?}", r.name);

            let ex = build_expr(&r.expr, &rules, &r.name, false);

            // TODO deal with recursive rules

            rules.push(Rule {
                name: r.name.clone(),
                ex,
            });
        }
        let ex = rules.last().unwrap().ex.clone();
        ex
    }

    /// Builds expression from pest expression.
    /// passes in current rule's name to deal with recursion.
    /// depth is used to prevent infinite recursion.
    fn build_expr(exp: &Expr, rules: &[Rule], this_name: &String, is_nested: bool) -> Ex {
        match exp {
            Expr::Rep(exp) => {
                Ex::RepEx(Rep(Box::new(build_expr(exp, rules, this_name, is_nested))))
            }
            Expr::RepExact(exp, count) => Ex::RepExactEx(RepExact((
                Box::new(build_expr(exp, rules, this_name, is_nested)),
                *count,
            ))),
            Expr::Str(str) => Ex::StrEx(Str(str.clone())),
            Expr::NegPred(exp) => Ex::NegPredEx(NegPred(Box::new(build_expr(
                exp, rules, this_name, is_nested,
            )))),
            Expr::Seq(a, b) => {
                //
                let a = build_expr(a, rules, this_name, is_nested);
                Ex::SeqEx(Seq(
                    Box::new(a),
                    Box::new(build_expr(b, rules, this_name, is_nested)),
                ))
            }
            Expr::Choice(a, b) => Ex::ChoiceEx(Choice(
                Box::new(build_expr(a, rules, this_name, is_nested)),
                Box::new(build_expr(b, rules, this_name, is_nested)),
            )),
            Expr::Opt(exp) => {
                Ex::OptEx(Opt(Box::new(build_expr(exp, rules, this_name, is_nested))))
            }
            Expr::Ident(ident) => {
                let ex = match ident.as_str() {
                    "ASCII_NONZERO_DIGIT" => Ex::ASCII_NONZERO_DIGIT,
                    "ASCII_DIGIT" => Ex::ASCII_DIGIT,
                    "ANY" => Ex::ANY,
                    "ASCII_HEX_DIGIT" => Ex::ASCII_HEX_DIGIT,
                    _ => {
                        if *ident == *this_name {
                            return Ex::NestedEx;
                        }

                        for rule in rules {
                            return rule.ex.clone();
                        }
                        panic!("couldnt find rule {:?}", ident);
                    }
                };
                ex
            }
            _ => unimplemented!(),
        }
    }

    // This method must be called when we know that there is enough
    // data remained starting from the offset to match the expression
    // at least once.
    //
    // returns the predicate and the offset from which the next expression
    // should be matched.
    // Returns multiple predicates if the expression caused multiple branches.
    // A top level expr always returns a single predicate, in which all branches
    // are coalesced.
    fn expr_to_pred(
        exp: &Ex,
        offset: usize,
        data_len: usize,
        is_top_level: bool,
    ) -> Vec<(Pred, usize)> {
        // if is_top_level {
        //     println!("top level exps {:?}", exp);
        // } else {
        //     println!("Non-top level exps {:?}", exp);
        // }
        match exp {
            Ex::SeqEx(s) => {
                let a = &s.0;
                let b = &s.1;

                if is_top_level && (offset + a.max_len() + b.max_len() < data_len) {
                    panic!();
                }
                if offset + a.min_len() + b.min_len() > data_len {
                    panic!();
                }

                // The first expression must not try to match in the
                // data of the next expression
                let pred1 = expr_to_pred(a, offset, data_len - b.min_len(), false);

                // interlace all branches
                let mut interlaced = Vec::new();

                for (p1, offset) in pred1.iter() {
                    // if the seq expr was top-level, the 2nd expr becomes top-level
                    let mut pred2 = expr_to_pred(b, *offset, data_len, is_top_level);
                    for (p2, offser_inner) in pred2.iter() {
                        let pred = Pred::And(vec![p1.clone(), p2.clone()]);
                        interlaced.push((pred, *offser_inner));
                    }
                }

                if is_top_level {
                    // coalesce all branches
                    let preds: Vec<Pred> = interlaced.into_iter().map(|(a, _b)| a).collect();
                    if preds.len() == 1 {
                        vec![(preds[0].clone(), 0)]
                    } else {
                        vec![(Pred::Or(preds), 0)]
                    }
                } else {
                    interlaced
                }
            }
            Ex::ChoiceEx(s) => {
                let a = &s.0;
                let b = &s.1;

                let mut skip_a = false;
                let mut skip_b = false;

                if is_top_level {
                    if offset + a.max_len() != data_len {
                        skip_a = true
                    }
                    if offset + b.max_len() != data_len {
                        skip_b = true;
                    }
                } else {
                    // if not top level, we may skip an expression when it will
                    // overflow the data len
                    if offset + a.min_len() > data_len {
                        skip_a = true
                    }
                    if offset + b.min_len() > data_len {
                        skip_b = true
                    }
                }

                if skip_a && skip_b {
                    panic!();
                }

                let mut preds_a = Vec::new();
                let mut preds_b = Vec::new();

                if !skip_a {
                    preds_a = expr_to_pred(a, offset, data_len, is_top_level);
                }
                if !skip_b {
                    preds_b = expr_to_pred(b, offset, data_len, is_top_level);
                }

                // combine all branches
                let mut combined = Vec::new();
                if preds_a.is_empty() {
                    combined = preds_b.clone();
                } else if preds_b.is_empty() {
                    combined = preds_a.clone();
                } else {
                    assert!(!(preds_a.is_empty() && preds_b.is_empty()));

                    combined.append(&mut preds_a);
                    combined.append(&mut preds_b);
                }

                if is_top_level {
                    // coalesce all branches
                    let preds: Vec<Pred> = combined.into_iter().map(|(a, _b)| a).collect();
                    if preds.len() == 1 {
                        vec![(preds[0].clone(), 0)]
                    } else {
                        vec![(Pred::Or(preds), 0)]
                    }
                } else {
                    combined
                }
            }
            Ex::RepEx(r) => {
                let e = &r.0;

                if offset + e.min_len() > data_len {
                    if is_top_level {
                        panic!();
                    }
                    // zero matches
                    return vec![];
                }

                let mut interlaced = Vec::new();

                let mut preds = expr_to_pred(&e, offset, data_len, false);

                // for (i, (pred, depth)) in preds.iter().enumerate() {
                //     println!("preds[{i}] (depth {depth}):");
                //     println!("{pred}");
                // }

                // Append single matches.
                interlaced.append(&mut preds.clone());

                let mut was_found = true;

                while was_found {
                    was_found = false;

                    for (pred_outer, offset_outer) in std::mem::take(&mut preds).into_iter() {
                        if offset_outer + e.min_len() > data_len {
                            // cannot match any more
                            continue;
                        }
                        let mut preds_inner = expr_to_pred(&e, offset_outer, data_len, false);

                        // for (i, (pred, depth)) in preds_inner.iter().enumerate() {
                        //     println!("preds[{i}] (depth {depth}):");
                        //     println!("{pred}");
                        // }
                        for (pred_inner, offset_inner) in preds_inner {
                            let pred = (
                                Pred::And(vec![pred_outer.clone(), pred_inner]),
                                offset_inner,
                            );
                            preds.push(pred);
                            was_found = true;
                        }
                    }
                    interlaced.append(&mut preds.clone());
                }

                // for (i, (pred, depth)) in interlaced.iter().enumerate() {
                //     println!("preds[{i}] (depth {depth}):");
                //     println!("{pred}");
                // }

                if is_top_level {
                    // drop all branches which do not match exactly at the data length
                    // border and coalesce the rest
                    let preds: Vec<Pred> = interlaced
                        .into_iter()
                        .filter(|(_a, b)| *b == data_len)
                        .map(|(a, _b)| a)
                        .collect();
                    if preds.is_empty() {
                        panic!()
                    }
                    if preds.len() == 1 {
                        vec![(preds[0].clone(), 0)]
                    } else {
                        // coalesce all branches
                        vec![(Pred::Or(preds), 0)]
                    }
                } else {
                    interlaced
                }
            }
            Ex::RepExactEx(r) => {
                let e = &r.0 .0;
                let count = r.0 .1;
                assert!(count > 0);

                if is_top_level && (offset + e.max_len() * count as usize <= data_len) {
                    panic!();
                }

                let mut preds = expr_to_pred(&e, offset, data_len, false);

                for i in 1..count {
                    for (pred_outer, offset_outer) in std::mem::take(&mut preds).into_iter() {
                        if offset_outer + e.min_len() > data_len {
                            // cannot match any more
                            continue;
                        }
                        let mut preds_inner = expr_to_pred(&e, offset_outer, data_len, false);
                        for (pred_inner, offset_inner) in preds_inner {
                            let pred = (
                                Pred::And(vec![pred_outer.clone(), pred_inner]),
                                offset_inner,
                            );
                            preds.push(pred);
                        }
                    }
                }

                if is_top_level {
                    // drop all branches which do not match exactly at the data length
                    // border and coalesce the rest
                    let preds: Vec<Pred> = preds
                        .into_iter()
                        .filter(|(_a, b)| *b != data_len)
                        .map(|(a, _b)| a)
                        .collect();
                    if preds.is_empty() {
                        panic!()
                    }

                    if preds.len() == 1 {
                        vec![(preds[0].clone(), 0)]
                    } else {
                        // coalesce all branches
                        vec![(Pred::Or(preds), 0)]
                    }
                } else {
                    preds
                }
            }
            Ex::NegPredEx(e) => {
                assert!(offset <= data_len);
                if offset == data_len {
                    // the internal expression cannot be match since there is no data left,
                    // this means that the negative expression matched
                    if is_top_level {
                        panic!("always true predicate doesnt make sense")
                    }

                    // TODO this is hacky.
                    return vec![(Pred::True, offset)];
                }

                let e = &e.0;
                let preds = expr_to_pred(&e, offset, data_len, is_top_level);

                let preds: Vec<Pred> = preds.into_iter().map(|(a, _b)| a).collect();
                let len = preds.len();

                // coalesce all branches, offset doesnt matter since those
                // offset will never be used anymore.
                let pred = if preds.len() == 1 {
                    Pred::Not(Box::new(preds[0].clone()))
                } else {
                    Pred::Not(Box::new(Pred::Or(preds)))
                };

                if is_top_level && len == 0 {
                    panic!()
                }

                // all offset if negative predicate are ignored since no matching
                // will be done from those offsets.
                vec![(pred, offset)]
            }
            Ex::OptEx(e) => {
                let e = &e.0;

                if is_top_level {
                    return vec![(Pred::True, 0)];
                }

                // add an always-matching branch
                let mut preds = vec![(Pred::True, offset)];

                if e.min_len() + offset <= data_len {
                    // try to match only if there is enough data
                    let mut p = expr_to_pred(&e, offset, data_len, is_top_level);
                    preds.append(&mut p);
                }

                preds
            }
            Ex::StrEx(s) => {
                if is_top_level && offset + s.0.len() != data_len {
                    panic!();
                }

                let mut preds = Vec::new();
                for (idx, byte) in s.0.clone().into_bytes().iter().enumerate() {
                    let a = Atom {
                        index: offset + idx,
                        op: CmpOp::Eq,
                        rhs: Rhs::Const(*byte),
                    };
                    preds.push(Pred::Atom(a));
                }

                if preds.len() == 1 {
                    vec![(preds[0].clone(), offset + s.0.len())]
                } else {
                    vec![(Pred::And(preds), offset + s.0.len())]
                }
            }
            Ex::ASCII_NONZERO_DIGIT => {
                if is_top_level && (offset + 1 != data_len) {
                    panic!();
                }

                let gte = Pred::Atom(Atom {
                    index: offset,
                    op: CmpOp::Gte,
                    rhs: Rhs::Const(49u8),
                });
                let lte = Pred::Atom(Atom {
                    index: offset,
                    op: CmpOp::Lte,
                    rhs: Rhs::Const(57u8),
                });
                vec![(Pred::And(vec![gte, lte]), offset + 1)]
            }
            Ex::ASCII_DIGIT => {
                if is_top_level && (offset + 1 != data_len) {
                    panic!();
                }

                let gte = Pred::Atom(Atom {
                    index: offset,
                    op: CmpOp::Gte,
                    rhs: Rhs::Const(48u8),
                });
                let lte = Pred::Atom(Atom {
                    index: offset,
                    op: CmpOp::Lte,
                    rhs: Rhs::Const(57u8),
                });
                vec![(Pred::And(vec![gte, lte]), offset + 1)]
            }
            Ex::ANY => {
                if is_top_level && (offset + 1 > data_len) {
                    panic!();
                }
                let start = offset;
                let end = min(offset + 4, data_len);
                let mut branches = Vec::new();
                for branch_end in start + 1..end {
                    branches.push((is_unicode(RangeSet::from(start..branch_end)), branch_end))
                }

                if is_top_level {
                    assert!(branches.len() == 1);
                }
                branches
            }
            _ => unimplemented!(),
        }
    }

    #[test]
    fn test_json_int() {
        use rand::{distr::Alphanumeric, rng, Rng};

        let grammar = include_str!("json_int.pest");

        // Parse the grammar file into Pairs (the grammar’s own parse tree)
        let pairs = meta::parse(meta::Rule::grammar_rules, grammar).expect("grammar parse error");

        // Optional: validate (reports duplicate rules, unreachable rules, etc.)
        validator::validate_pairs(pairs.clone()).expect("invalid grammar");

        // 4) Convert the parsed pairs into the stable AST representation
        let rules_ast: Vec<ast::Rule> = consume_rules(pairs).unwrap();

        let exp = build_rules(&rules_ast);

        // 5) Inspect the AST however you like For a quick look, the Debug print is the
        //    safest (works across versions)
        for rule in &rules_ast {
            println!("{:#?}", rule);
        }

        const LENGTH: usize = 7; // Adjustable constant

        let pred = expr_to_pred(&exp, 0, LENGTH, true);
        assert!(pred.len() == 1);
        let pred = &pred[0].0;

        let circ = Compiler::new().compile(&pred);

        println!("{:?} and gates", circ.and_count());

        for i in 0..1000000 {
            let s: String = rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(LENGTH)
                .map(char::from)
                .collect();

            let out = eval_pred(pred, s.as_bytes());

            let is_int = s.chars().all(|c| c.is_ascii_digit()) && !s.starts_with('0');

            if out != is_int {
                println!("failed at index {:?} with {:?}", i, s);
            }
            assert_eq!(out, is_int)
        }
    }

    #[test]
    fn test_json_str() {
        use rand::{distr::Alphanumeric, rng, Rng};
        const LENGTH: usize = 10; // Adjustable constant

        let grammar = include_str!("json_str.pest");

        // Parse the grammar file into Pairs (the grammar’s own parse tree)
        let pairs = meta::parse(meta::Rule::grammar_rules, grammar).expect("grammar parse error");

        // Optional: validate (reports duplicate rules, unreachable rules, etc.)
        validator::validate_pairs(pairs.clone()).expect("invalid grammar");

        // 4) Convert the parsed pairs into the stable AST representation
        let rules_ast: Vec<ast::Rule> = consume_rules(pairs).unwrap();

        for rule in &rules_ast {
            println!("{:#?}", rule);
        }

        let exp = build_rules(&rules_ast);

        for len in LENGTH..LENGTH + 7 {
            let pred = expr_to_pred(&exp, 0, len, true);
            assert!(pred.len() == 1);
            let pred = &pred[0].0;

            let circ = Compiler::new().compile(pred);

            println!(
                "JSON string length: {:?}; circuit AND gate count {:?}",
                len,
                circ.and_count()
            );
        }
    }

    #[test]
    fn test_choice() {
        let a = Expr::Ident("ASCII_NONZERO_DIGIT".to_string());
        let b = Expr::Ident("ASCII_DIGIT".to_string());
        let rule = ast::Rule {
            name: "test".to_string(),
            ty: ast::RuleType::Atomic,
            expr: Expr::Choice(Box::new(a), Box::new(b)),
        };

        let exp = build_rules(&vec![rule]);
        let pred = expr_to_pred(&exp, 0, 1, true);
        assert!(pred.len() == 1);
        let pred = &pred[0].0;

        println!("pred is {:?}", pred);
    }

    #[test]
    fn test_seq() {
        let a = Expr::Ident("ASCII_NONZERO_DIGIT".to_string());
        let b = Expr::Ident("ASCII_DIGIT".to_string());
        let rule = ast::Rule {
            name: "test".to_string(),
            ty: ast::RuleType::Atomic,
            expr: Expr::Seq(Box::new(a), Box::new(b)),
        };

        let exp = build_rules(&vec![rule]);
        let pred = expr_to_pred(&exp, 0, 2, true);
        assert!(pred.len() == 1);
        let pred = &pred[0].0;

        println!("pred is {:?}", pred);
    }

    #[test]
    fn test_rep() {
        let a = Expr::Ident("ASCII_NONZERO_DIGIT".to_string());
        let b = Expr::Ident("ASCII_DIGIT".to_string());

        let rule = ast::Rule {
            name: "test".to_string(),
            ty: ast::RuleType::Atomic,
            expr: Expr::Rep(Box::new(a)),
        };

        let exp = build_rules(&vec![rule]);
        let pred = expr_to_pred(&exp, 0, 3, true);
        assert!(pred.len() == 1);
        let pred = &pred[0].0;

        println!("pred is {:?}", pred);
    }

    #[test]
    fn test_rep_choice() {
        const LENGTH: usize = 5; // Adjustable constant

        let a = Expr::Ident("ASCII_NONZERO_DIGIT".to_string());
        let b = Expr::Ident("ASCII_DIGIT".to_string());
        // Number of predicates needed to represent the expressions.
        let a_weight = 2usize;
        let b_weight = 2usize;

        let rep_a = Expr::Rep(Box::new(a));
        let rep_b = Expr::Rep(Box::new(b));

        let rule = ast::Rule {
            name: "test".to_string(),
            ty: ast::RuleType::Atomic,
            expr: Expr::Choice(Box::new(rep_a), Box::new(rep_b)),
        };

        let exp = build_rules(&vec![rule]);
        let pred = expr_to_pred(&exp, 0, LENGTH, true);
        assert!(pred.len() == 1);
        let pred = &pred[0].0;

        println!("pred is {}", pred);
        // This is for sanity that no extra predicates are being added.
        assert_eq!(pred.leaves(), a_weight * LENGTH + b_weight * LENGTH);
    }

    #[test]
    fn test_neg_choice() {
        let a = Expr::Str("4".to_string());
        let b = Expr::Str("5".to_string());
        let choice = Expr::Choice(Box::new(a), Box::new(b));
        let neg_choice = Expr::NegPred(Box::new(choice));
        let c = Expr::Str("a".to_string());
        let d = Expr::Str("BC".to_string());
        let choice2 = Expr::Choice(Box::new(c), Box::new(d));

        let rule = ast::Rule {
            name: "test".to_string(),
            ty: ast::RuleType::Atomic,
            expr: Expr::Seq(Box::new(neg_choice), Box::new(choice2)),
        };

        let exp = build_rules(&vec![rule]);
        let pred = expr_to_pred(&exp, 0, 2, true);
        assert!(pred.len() == 1);
        let pred = &pred[0].0;

        println!("pred is {:?}", pred);
        assert_eq!(pred.leaves(), 4);
    }
}
