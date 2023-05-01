use syn::{
    parse::Parse, parse_quote, visit_mut::VisitMut, Expr, FnArg, Ident, ItemFn, Meta, Path, Token,
    Type,
};

use crate::map::map_primitive_type;

pub struct PrimitiveTypeReplace;

impl VisitMut for PrimitiveTypeReplace {
    fn visit_type_mut(&mut self, ty: &mut Type) {
        match ty {
            Type::Slice(slice_type) => self.visit_type_mut(&mut slice_type.elem),
            Type::Array(array_type) => self.visit_type_mut(&mut array_type.elem),
            Type::Path(path_type) if path_type.path.segments.len() == 1 => {
                let new_ty = map_primitive_type(&path_type.path.segments[0].ident);
                *ty = parse_quote!(::mpc_circuits::Tracer<'trace, ::mpc_circuits::types::#new_ty>)
            }
            Type::Reference(reference_type) => self.visit_type_mut(&mut reference_type.elem),
            Type::Tuple(tuple_type) => tuple_type
                .elems
                .iter_mut()
                .for_each(|ty| self.visit_type_mut(ty)),
            _ => return,
        }
    }
}

pub struct FnSigTypeReplace;

impl VisitMut for FnSigTypeReplace {
    fn visit_item_fn_mut(&mut self, i: &mut ItemFn) {
        for arg in &mut i.sig.inputs {
            InputArgReplace.visit_fn_arg_mut(arg)
        }
        ReturnsTypeReplace.visit_return_type_mut(&mut i.sig.output);
    }
}

pub struct InputArgReplace;

impl VisitMut for InputArgReplace {
    fn visit_fn_arg_mut(&mut self, i: &mut FnArg) {
        if let FnArg::Typed(arg) = i {
            if let Some(idx) = arg
                .attrs
                .iter()
                .position(|attr| attr.path.is_ident("constant"))
            {
                arg.attrs.remove(idx);
                return;
            }
            PrimitiveTypeReplace.visit_type_mut(&mut arg.ty);
        }
    }
}

pub struct ReturnsTypeReplace;

impl VisitMut for ReturnsTypeReplace {
    fn visit_return_type_mut(&mut self, i: &mut syn::ReturnType) {
        if let syn::ReturnType::Type(_, ty) = i {
            PrimitiveTypeReplace.visit_type_mut(ty);
        }
    }
}

pub struct CallRename {
    pub(crate) config: CallRenameConfig,
}

#[derive(Debug)]
pub struct CallRenameConfig {
    path: Path,
    new_path: Option<Path>,
}

impl Parse for CallRenameConfig {
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

        let new_path = if let Some(Meta::Path(path)) = meta.pop() {
            Some(path)
        } else {
            None
        };

        Ok(Self { path, new_path })
    }
}

impl VisitMut for CallRename {
    fn visit_expr_call_mut(&mut self, i: &mut syn::ExprCall) {
        if let Expr::Path(path) = &mut (*i.func) {
            if path.path == self.config.path {
                if let Some(new_path) = &self.config.new_path {
                    path.path = new_path.clone();
                } else {
                    let path_segment = path.path.segments.last_mut().unwrap();
                    path_segment.ident = Ident::new(
                        &format!(
                            "{}_{}",
                            path_segment.ident.to_string(),
                            crate::DEFAULT_SUFFIX
                        ),
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
