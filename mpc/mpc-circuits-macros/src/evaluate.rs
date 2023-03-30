use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parse, parse_macro_input, parse_quote, punctuated::Punctuated, Expr, Token, Type,
};

#[derive(Debug)]
#[allow(unused)]
struct EvaluateMacroInput {
    circ: Expr,
    comma: Token![,],
    fn_token: Token![fn],
    paren_token: syn::token::Paren,
    values: Punctuated<Expr, Token![,]>,
    right_arrow: Token![->],
    return_type: Type,
}

impl Parse for EvaluateMacroInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let content;
        Ok(Self {
            circ: input.parse()?,
            comma: input.parse()?,
            fn_token: input.parse()?,
            paren_token: syn::parenthesized!(content in input),
            values: content.parse_terminated(Expr::parse)?,
            right_arrow: input.parse()?,
            return_type: input.parse()?,
        })
    }
}

pub(crate) fn evaluate_impl(item: TokenStream) -> TokenStream {
    let EvaluateMacroInput {
        circ,
        values,
        return_type,
        ..
    } = parse_macro_input!(item as EvaluateMacroInput);

    let input_args: Vec<Expr> = values.into_iter().collect();

    let return_count = match &return_type {
        Type::Tuple(tuple) => tuple.elems.len(),
        _ => 1,
    };

    let return_expr: Expr = if return_count > 1 {
        let expr = format!(
            "({})",
            "outputs.pop().unwrap().try_into()?, ".repeat(return_count)
        );
        syn::parse_str(&expr).unwrap()
    } else {
        parse_quote!(outputs.pop().unwrap().try_into()?)
    };

    quote! {
        {
            use mpc_circuits::{CircuitError, types::Value};

            let eval = || -> Result<#return_type, CircuitError> {
                if #circ.outputs().len() != #return_count {
                    return Err(CircuitError::InvalidOutputCount(
                        #circ.outputs().len(),
                        #return_count,
                    ));
                }

                let mut outputs = #circ.evaluate(&[#(#input_args.into()),*])?;
                outputs.reverse();

                Ok(#return_expr)
            };

            eval()
        }
    }
    .into()
}
