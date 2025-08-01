#[allow(warnings)]
mod bindings;

use bindings::Guest;

struct Component;

impl Guest for Component {
    fn main(input: Vec<u8>) -> Vec<u8> {
        todo!()
    }
}

bindings::export!(Component with_types_in bindings);
