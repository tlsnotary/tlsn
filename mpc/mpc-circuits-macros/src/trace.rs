use proc_macro::TokenStream;
use quote::{quote, ToTokens};
use syn::{
    parse::Parse, parse_macro_input, parse_quote, spanned::Spanned, visit_mut::VisitMut, Expr,
    FnArg, Ident, ItemFn, Meta, Pat, ReturnType, Stmt, Token, Type,
};

use crate::{traits::IsPrimitiveType, visitors::FnSigTypeReplace, DEFAULT_SUFFIX};

struct StripConstArgAttr;

impl VisitMut for StripConstArgAttr {
    fn visit_item_fn_mut(&mut self, i: &mut ItemFn) {
        for arg in &mut i.sig.inputs {
            if let syn::FnArg::Typed(arg) = arg {
                arg.attrs.retain(|attr| !attr.path.is_ident("constant"));
            }
        }
    }
}

struct TraceConfig {
    cache: bool,
    suffix: String,
}

impl Parse for TraceConfig {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let meta: Vec<Meta> = input
            .parse_terminated::<Meta, Token![,]>(Meta::parse)?
            .into_iter()
            .collect();

        let mut cache = false;
        let mut suffix = DEFAULT_SUFFIX.to_string();

        for meta in meta {
            match meta {
                Meta::Path(path) if path.is_ident("cache") => cache = true,
                Meta::NameValue(name_value) if name_value.path.is_ident("suffix") => {
                    if let syn::Lit::Str(lit_str) = name_value.lit {
                        suffix = lit_str.value();
                    } else {
                        return Err(syn::Error::new(
                            name_value.lit.span(),
                            "Expected string literal",
                        ));
                    }
                }
                _ => {
                    return Err(syn::Error::new(
                        meta.span(),
                        "Expected `cache` or `suffix = \"...\"`",
                    ));
                }
            }
        }

        Ok(TraceConfig { cache, suffix })
    }
}

pub(crate) fn trace_impl(args: TokenStream, item: TokenStream) -> TokenStream {
    let TraceConfig { cache, suffix } = parse_macro_input!(args as TraceConfig);
    let mut item_fn = parse_macro_input!(item as ItemFn);
    let fn_name = item_fn.sig.ident.clone();

    // Duplicate the function
    let mut trace_fn = item_fn.clone();

    // Strip the #[constant] attribute from original function
    StripConstArgAttr.visit_item_fn_mut(&mut item_fn);
    // Strip any #[dep] attribute from original function
    item_fn.attrs.retain(|attr| !attr.path.is_ident("dep"));

    // insert 'trace lifetime into generics
    trace_fn.sig.generics.params.insert(0, parse_quote!('trace));

    // add _trace suffix to function ident
    trace_fn.sig.ident = Ident::new(
        &format!("{}_{}", fn_name.to_string(), suffix),
        trace_fn.sig.ident.span(),
    );

    // collect all dynamic arguments
    let dyn_args: Vec<_> = trace_fn
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(arg) = arg {
                if !arg.attrs.iter().any(|attr| attr.path.is_ident("constant")) {
                    Some(arg.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    let mut dyn_arg_ident: Vec<Ident> = Vec::with_capacity(dyn_args.len());
    let mut dyn_arg_stmt: Vec<Stmt> = Vec::with_capacity(dyn_args.len());
    for arg in dyn_args.iter() {
        let ident = if let Pat::Ident(ident) = &(*arg.pat) {
            ident.ident.clone()
        } else {
            panic!("Unsupported argument type: {:?}", arg.to_token_stream())
        };
        dyn_arg_ident.push(ident.clone());

        let expr = match &(*arg.ty) {
            Type::Path(_) if arg.ty.is_primitive() => {
                let ty = (*arg.ty).clone();

                parse_quote! { let #ident = builder.add_input::<#ty>(); }
            }
            Type::Array(arr) if arr.elem.is_primitive() => {
                let ty = (*arr.elem).clone();
                let len = (arr.len).clone();

                match &len {
                    Expr::Lit(literal) => {
                        matches!(literal.lit, syn::Lit::Int(_))
                    }
                    Expr::Path(path) if path.path.segments.len() == 1 => path.path.segments[0]
                        .ident
                        .to_string()
                        .chars()
                        .all(|c| c.is_uppercase()),
                    _ => panic!("Unsupported argument type: {:?}", arg.to_token_stream()),
                };

                parse_quote! { let #ident = builder.add_array_input::<#ty, #len>(); }
            }
            _ => {
                panic!("Unsupported argument type: {:?}", arg.to_token_stream())
            }
        };
        dyn_arg_stmt.push(expr);
    }

    // collect all the constant arguments
    let const_args: Vec<_> = trace_fn
        .sig
        .inputs
        .iter()
        .filter_map(|arg| {
            if let FnArg::Typed(arg) = arg {
                if arg.attrs.iter().any(|attr| attr.path.is_ident("constant")) {
                    Some(arg.clone())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect();

    let const_arg_ident: Vec<_> = const_args
        .iter()
        .map(|arg| {
            if let Pat::Ident(ident) = &(*arg.pat) {
                ident.ident.clone()
            } else {
                panic!("Unsupported argument type: {:?}", arg.to_token_stream())
            }
        })
        .collect();
    let const_arg_ty: Vec<_> = const_args.iter().map(|arg| &arg.ty).collect();
    let const_arg_ty = quote!((#(#const_arg_ty),*));

    // replace primitive types
    FnSigTypeReplace.visit_item_fn_mut(&mut trace_fn);

    // add builder argument
    trace_fn.sig.inputs.insert(
        0,
        parse_quote!(state: &'trace std::cell::RefCell<::mpc_circuits::BuilderState>),
    );

    let return_type = if let ReturnType::Type(_, ty) = &trace_fn.sig.output {
        (**ty).clone()
    } else {
        panic!(
            "Unsupported return type: {:?}",
            trace_fn.sig.output.to_token_stream()
        )
    };

    let block = trace_fn.block.clone();

    let output_expr: Vec<Expr> = if let Type::Tuple(tuple_type) = &return_type {
        (0..tuple_type.elems.len())
            .map(|i| parse_quote!(builder.add_output(output.#i)))
            .collect()
    } else {
        vec![parse_quote!(builder.add_output(output))]
    };

    let return_expr: Expr = if let Type::Tuple(tuple_type) = &return_type {
        let i = 0..tuple_type.elems.len();
        parse_quote!((#(::mpc_circuits::Tracer::new(state, output[#i].clone().try_into().unwrap())),*))
    } else {
        parse_quote!(::mpc_circuits::Tracer::new(
            state,
            output[0].clone().try_into().unwrap()
        ))
    };

    trace_fn.block = if cache {
        parse_quote! {
            {
                use std::{cell::RefCell, collections::HashMap, sync::Mutex};
                use ::mpc_circuits::{once_cell::sync::Lazy, CircuitBuilder, Circuit, ops::*};
                static CACHE: Lazy<Mutex<HashMap<#const_arg_ty, Circuit>>> = Lazy::new(|| Mutex::new(HashMap::new()));
                let mut cache = CACHE.lock().unwrap();
                let circ = {
                    if let Some(cached) = cache.get(&(#(#const_arg_ident),*)) {
                        cached
                    } else {
                        let builder = CircuitBuilder::new();

                        let output = {
                            #(#dyn_arg_stmt)*
                            #block
                        };

                        #(#output_expr;)*

                        let circ = builder.build().expect(stringify!(#fn_name should build successfully));

                        cache.insert((#(#const_arg_ident),*), circ);
                        cache.get(&(#(#const_arg_ident),*)).unwrap()
                    }
                };

                #(
                    let #dyn_arg_ident = #dyn_arg_ident.into();
                )*

                let output = state.borrow_mut().append(circ, &[#(#dyn_arg_ident),*]).expect(stringify!(#fn_name should append successfully));

                #return_expr
            }
        }
    } else {
        parse_quote! {
            #block
        }
    };

    let mut stream: TokenStream = item_fn.to_token_stream().into();

    let traced_fn_stream: TokenStream = trace_fn.to_token_stream().into();

    stream.extend(traced_fn_stream);

    stream
}
