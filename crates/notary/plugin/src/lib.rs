use extism_pdk::*;
use serde::{Deserialize, Serialize};

const VOWELS: &[char] = &['a', 'A', 'e', 'E', 'i', 'I', 'o', 'O', 'u', 'U'];

#[derive(Serialize, Deserialize, ToBytes, FromBytes)]
#[encoding(Json)]
struct Output {
    count: i32,
}

#[host_fn]
extern "ExtismHost" {
    fn add_extra(count: Output) -> Output;
}

#[plugin_fn]
pub unsafe fn count_vowels<'a>(input: String) -> FnResult<Output> {
    let mut count = 0;
    for ch in input.chars() {
        if VOWELS.contains(&ch) {
            count += 1;
        }
    }

    info!("Counted {} vowels in input: {}", count, input);

    let output = Output { count };
    let output = unsafe { add_extra(output)? };
    Ok(output)
}
