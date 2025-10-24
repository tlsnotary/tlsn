mod generated {
    wit_bindgen::generate!({
        world: "plugin",
        path: "../sdk-core/wit/tlsn.wit",
        pub_export_macro: true,
    });

    impl From<std::task::Poll<Result<Vec<u8>, String>>> for PollReturn {
        #[inline]
        fn from(value: std::task::Poll<Result<Vec<u8>, String>>) -> Self {
            match value {
                std::task::Poll::Ready(ret) => PollReturn::Ready(ret),
                std::task::Poll::Pending => PollReturn::Pending,
            }
        }
    }

    unsafe extern "Rust" {
        fn __tlsn_entry_trampoline(
            arg: Vec<u8>,
        ) -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<Vec<u8>, String>>>>;
    }

    thread_local! {
        static MAIN: ::std::cell::RefCell<Option<::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<Vec<u8>, String>>>>>> = ::std::cell::RefCell::new(None);
    }

    struct Plugin;
    impl Guest for Plugin {
        fn start(arg: Vec<u8>) -> () {
            MAIN.with_borrow_mut(|fut| {
                if fut.is_some() {
                    panic!("main future already set");
                }

                *fut = Some(unsafe { __tlsn_entry_trampoline(arg) });
            })
        }

        fn poll() -> PollReturn {
            MAIN.with_borrow_mut(|fut| {
                let Some(fut) = fut.as_mut() else {
                    panic!("main future not set, must call start first");
                };

                let mut cx = ::std::task::Context::from_waker(::std::task::Waker::noop());
                fut.as_mut().poll(&mut cx).into()
            })
        }
    }
    export!(Plugin);
}

pub(crate) use generated::tlsn::tlsn::*;

#[macro_export]
macro_rules! entry {
    ($path:path) => {
        #[unsafe(no_mangle)]
        extern "Rust" fn __tlsn_entry_trampoline(
            arg: Vec<u8>,
        ) -> ::std::pin::Pin<Box<dyn ::std::future::Future<Output = Result<Vec<u8>, String>>>> {
            #[inline(always)]
            fn assert_async<F>(f: F) -> F
            where
                F: Future<Output = Result<Vec<u8>, String>>,
            {
                f
            }

            Box::pin(assert_async($path(arg)))
        }
    };
}
