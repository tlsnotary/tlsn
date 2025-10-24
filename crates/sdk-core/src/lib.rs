pub(crate) mod instance;
pub(crate) mod io;
pub(crate) mod prover;
pub(crate) mod provider;
pub(crate) mod verifier;
pub(crate) mod wasm;
mod wasmtime;

pub use provider::IoProvider;
pub use wasmtime::Wasmtime;

use std::{
    future::poll_fn,
    sync::{Arc, Mutex},
    task::Poll,
};

use crate::{instance::State, wasm::WasmRuntime};

#[derive(Debug)]
pub struct Error;

pub struct Plugin {
    pub manifest: Manifest,
    pub binary: Binary,
}

pub struct Manifest {}

/// Plugin WASM binary.
pub struct Binary(pub Vec<u8>);

pub struct Runtime<T, I> {
    wasm: T,
    io_provider: I,
}

impl<T, I> Runtime<T, I> {
    pub fn new(wasm: T, io_provider: I) -> Self {
        Self { wasm, io_provider }
    }
}

impl<T, I> Runtime<T, I>
where
    T: WasmRuntime,
    I: IoProvider,
{
    pub async fn run_plugin(&mut self, plugin: &Plugin, input: &[u8]) -> Vec<u8> {
        let wasm = self.wasm.load(&plugin.binary).unwrap();

        let instance = Arc::new(Mutex::new(instance::Instance::default()));
        let id = self
            .wasm
            .instantiate(wasm, instance.clone(), input)
            .unwrap();

        let mut output = None;
        let mut ready_0 = false;
        let mut ready_1 = false;
        let output = poll_fn(|cx_std| {
            let wants_call = instance.lock().unwrap().cx.waker.wants_call();
            if !ready_0
                && wants_call
                && let Poll::Ready(res) = self.wasm.poll(id).unwrap()
            {
                output = Some(res.inspect(|data| {
                    println!("plugin output: {}", String::from_utf8_lossy(data));
                }));
                ready_0 = true;
            }

            let mut instance = instance.lock().unwrap();
            if !ready_0 {
                if instance.cx.waker.wants_wake() {
                    cx_std.waker().wake_by_ref();
                } else {
                    panic!("plugin isn't waiting for anything");
                }
            }

            if !ready_1 {
                let instance = &mut (*instance);
                if let Poll::Ready(res) =
                    instance
                        .state
                        .poll(cx_std, &mut instance.cx, &mut self.io_provider)
                {
                    res.unwrap();
                    ready_1 = true;
                }
            }

            if ready_0 && ready_1 {
                return Poll::Ready(Ok::<_, Error>(output.take().unwrap()));
            } else {
                Poll::Pending
            }
        })
        .await
        .unwrap();

        output.unwrap()
    }
}
