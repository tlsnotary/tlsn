use syn::{parse_quote, visit_mut::VisitMut, FnArg, ItemFn, Type};

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
