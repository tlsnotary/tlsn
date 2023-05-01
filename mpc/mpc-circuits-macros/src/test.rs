use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parse, parse_macro_input, parse_quote, punctuated::Punctuated, Expr, Path, Token, Type,
};

#[derive(Debug)]
#[allow(unused)]
struct TestMacroInput {
    circ: Expr,
    comma_0: Token![,],
    test_fn: Path,
    comma_1: Token![,],
    fn_token: Token![fn],
    paren_token: syn::token::Paren,
    values: Punctuated<Expr, Token![,]>,
    right_arrow: Token![->],
    return_type: Type,
}

impl Parse for TestMacroInput {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let content;
        Ok(Self {
            circ: input.parse()?,
            comma_0: input.parse()?,
            test_fn: input.parse()?,
            comma_1: input.parse()?,
            fn_token: input.parse()?,
            paren_token: syn::parenthesized!(content in input),
            values: content.parse_terminated(Expr::parse)?,
            right_arrow: input.parse()?,
            return_type: input.parse()?,
        })
    }
}

pub(crate) fn test_impl(item: TokenStream) -> TokenStream {
    let TestMacroInput {
        circ,
        test_fn,
        values,
        return_type,
        ..
    } = parse_macro_input!(item as TestMacroInput);

    let input_args: Vec<Expr> = values.into_iter().collect();

    let return_count = match &return_type {
        Type::Tuple(tuple) => tuple.elems.len(),
        _ => 1,
    };

    let return_expr: Expr = if return_count > 1 {
        let expr = format!(
            "({})",
            "outputs.pop().unwrap().try_into().unwrap(), ".repeat(return_count)
        );
        syn::parse_str(&expr).unwrap()
    } else {
        parse_quote!(outputs.pop().unwrap().try_into().unwrap())
    };

    quote! {
        {
            let mut outputs = #circ.evaluate(&[#(#input_args.into()),*]).unwrap();
            outputs.reverse();
            let outputs: #return_type = #return_expr;

            let expected = #test_fn(#(#input_args),*);

            assert_eq!(outputs, expected);
        }
    }
    .into()
}
