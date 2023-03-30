use quote::ToTokens;
use syn::Type;

pub trait IsEncodableType {
    /// Returns `true` if the type is an encodable type.
    fn is_encodable(&self, level: usize) -> bool;
}

impl IsEncodableType for Type {
    fn is_encodable(&self, level: usize) -> bool {
        match self {
            Type::Tuple(tuple) if level < 2 => {
                tuple.elems.iter().all(|ty| ty.is_encodable(level + 1))
            }
            Type::Array(arr) if level < 2 => arr.elem.is_encodable(level + 1),
            Type::Path(path_type) if level < 3 => path_type.path.segments.len() == 1,
            _ => false,
        }
    }
}

pub trait IsPrimitiveType {
    /// Returns `true` if the type is a primitive type.
    fn is_primitive(&self) -> bool;
}

impl IsPrimitiveType for Type {
    fn is_primitive(&self) -> bool {
        match self {
            Type::Path(path_type) => {
                let path = path_type.path.clone().into_token_stream().to_string();
                path == "u8"
                    || path == "u16"
                    || path == "u32"
                    || path == "u64"
                    || path == "u128"
                    || path == "bool"
            }
            _ => false,
        }
    }
}
