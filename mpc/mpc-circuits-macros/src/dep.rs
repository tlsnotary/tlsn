use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse::Parse, parse_macro_input, parse_quote, visit_mut::VisitMut, Expr, Ident, ItemFn, Meta,
    Path, Token,
};

use crate::DEFAULT_SUFFIX;

struct CallRename {
    config: DepConfig,
}

impl VisitMut for CallRename {
    fn visit_expr_call_mut(&mut self, i: &mut syn::ExprCall) {
        if let Expr::Path(path) = &mut (*i.func) {
            if path.path == self.config.path {
                if let Some(new_path) = &self.config.trace_path {
                    path.path = new_path.clone();
                } else {
                    let path_segment = path.path.segments.last_mut().unwrap();
                    path_segment.ident = Ident::new(
                        &format!("{}_{}", path_segment.ident.to_string(), DEFAULT_SUFFIX),
                        path_segment.ident.span(),
                    );
                }

                // pass builder argument to call
                i.args.insert(0, parse_quote!(state));
            }

            // process nested calls
            for arg in &mut i.args {
                if let Expr::Call(call) = arg {
                    self.visit_expr_call_mut(call);
                }
            }
        }
    }
}

#[derive(Debug)]
struct DepConfig {
    path: Path,
    trace_path: Option<Path>,
}

impl Parse for DepConfig {
    fn parse(input: syn::parse::ParseStream) -> syn::Result<Self> {
        let mut meta: Vec<Meta> = input
            .parse_terminated::<Meta, Token![,]>(Meta::parse)?
            .into_iter()
            .rev()
            .collect();

        let path = if let Some(Meta::Path(path)) = meta.pop() {
            path
        } else {
            return Err(syn::Error::new(
                input.span(),
                "Expected path of function to trace",
            ));
        };

        let trace_path = if let Some(Meta::Path(path)) = meta.pop() {
            Some(path)
        } else {
            None
        };

        Ok(Self { path, trace_path })
    }
}

pub(crate) fn dep_impl(args: TokenStream, item: TokenStream) -> TokenStream {
    let config = parse_macro_input!(args as DepConfig);
    let mut item_fn = parse_macro_input!(item as ItemFn);

    CallRename { config }.visit_item_fn_mut(&mut item_fn);

    quote!(#item_fn).into()
}
