#![feature(portable_simd)]
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn transpose_matrix(m: &mut [u8], row_length: usize) {
    // Check that data can be read as a matrix
}

#[cfg(target_arch = "wasm32")]
#[target_feature(enable = "simd128")]
unsafe fn m_u8x16_bitmask(x: [u8; 16]) -> u16 {
    use std::arch::wasm32::{u8x16, u8x16_bitmask};
    let v128 = u8x16(
        x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7], x[8], x[9], x[10], x[11], x[12], x[13],
        x[14], x[15],
    );
    u8x16_bitmask(v128)
}
