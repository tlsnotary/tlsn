mod dep;
mod evaluate;
pub(crate) mod map;
mod trace;
pub(crate) mod traits;
pub(crate) mod visitors;

use proc_macro::TokenStream;

const DEFAULT_SUFFIX: &str = "trace";

#[proc_macro_attribute]
pub fn dep(args: TokenStream, item: TokenStream) -> TokenStream {
    dep::dep_impl(args, item)
}

#[proc_macro_attribute]
pub fn trace(args: TokenStream, item: TokenStream) -> TokenStream {
    trace::trace_impl(args, item)
}

#[proc_macro]
pub fn evaluate(item: TokenStream) -> TokenStream {
    evaluate::evaluate_impl(item)
}
