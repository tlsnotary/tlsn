use syn::Ident;

pub fn map_primitive_type(ident: &Ident) -> Ident {
    match ident.to_string().as_str() {
        "bool" => Ident::new("Bit", ident.span()),
        "u8" => Ident::new("U8", ident.span()),
        "u16" => Ident::new("U16", ident.span()),
        "u32" => Ident::new("U32", ident.span()),
        "u64" => Ident::new("U64", ident.span()),
        "u128" => Ident::new("U128", ident.span()),
        _ => ident.clone(),
    }
}
