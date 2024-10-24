pub mod http;

macro_rules! define_fixture {
    ($name:ident, $doc:tt, $path:tt) => {
        #[doc = $doc]
        ///
        /// ```text
        #[doc = include_str!($path)]
        /// ```
        pub const $name: &[u8] = include_bytes!($path);
    };
}

pub(crate) use define_fixture;
