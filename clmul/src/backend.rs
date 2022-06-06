//! Carryless multiplication backends

#[cfg_attr(not(target_pointer_width = "64"), path = "backend/soft32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "backend/soft64.rs")]
mod soft;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(all(target_arch = "aarch64", feature = "armv8", not(feature = "force-soft")))] {
        mod autodetect;
        mod pmull;
        pub use crate::backend::autodetect::Clmul;
    } else if #[cfg(all(
        any(target_arch = "x86_64", target_arch = "x86"),
        not(feature = "force-soft")
    ))] {
        mod autodetect;
        mod clmul;
        pub use crate::backend::autodetect::Clmul;
    } else {
        pub use crate::backend::soft::Clmul;
    }
}
