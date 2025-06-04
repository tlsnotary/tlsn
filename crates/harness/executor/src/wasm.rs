use std::{cell::RefCell, panic::PanicHookInfo};

use gloo_utils::format::JsValueSerdeExt;
use js_sys::Function;
use wasm_bindgen::prelude::*;

use harness_core::{
    ExecutorConfig,
    rpc::{Cmd, CmdOutput, RpcError},
    test::{TestOutput, TestStatus},
};

use crate::Executor;

pub use tlsn_wasm::*;

unsafe extern "C" {
    fn __wasm_call_ctors();
}

#[wasm_bindgen(start)]
pub fn main() {
    unsafe { __wasm_call_ctors() };
}

thread_local! {
    static PANIC_CB: RefCell<Option<Function>> = RefCell::new(None);
}

#[wasm_bindgen]
pub struct WasmExecutor(Executor);

#[wasm_bindgen]
impl WasmExecutor {
    #[wasm_bindgen(constructor)]
    pub fn new(config: JsValue) -> Self {
        let config: ExecutorConfig = config.into_serde().unwrap();
        Self(Executor::new(config))
    }

    pub async fn call(
        &mut self,
        cmd: JsValue,
        panic_callback: &Function,
    ) -> Result<JsValue, JsError> {
        let cmd: Cmd = cmd.into_serde()?;

        PANIC_CB.with(|callback| {
            *callback.borrow_mut() = Some(panic_callback.clone());
        });

        let panic_msg = {
            let cmd = cmd.clone();
            move |info: &PanicHookInfo<'_>| {
                let payload = if let Some(s) = info.payload().downcast_ref::<&str>() {
                    Some(s.to_string())
                } else if let Some(s) = info.payload().downcast_ref::<String>() {
                    Some(s.clone())
                } else {
                    None
                };

                let reason = match (info.location(), payload) {
                    (Some(location), Some(payload)) => Some(format!(
                        "\nwasm executor panicked at {}:{}:{}:\n{}",
                        location.file(),
                        location.line(),
                        location.column(),
                        payload
                    )),
                    (Some(location), None) => Some(format!(
                        "\nwasm executor panicked at {}:{}:{}",
                        location.file(),
                        location.line(),
                        location.column()
                    )),
                    (None, Some(payload)) => Some(payload),
                    _ => None,
                };

                let output: Result<CmdOutput, RpcError> = match cmd {
                    Cmd::Test(_) => Ok(CmdOutput::Test(TestOutput {
                        status: TestStatus::Failed { reason },
                    })),
                    _ => Ok(CmdOutput::Fail { reason }),
                };

                output
            }
        };

        std::panic::set_hook(Box::new(move |info| {
            PANIC_CB.with(|callback| {
                if let Some(callback) = callback.borrow().as_ref() {
                    let _ = callback.call1(
                        &JsValue::NULL,
                        &JsValue::from_serde(&panic_msg(info)).unwrap(),
                    );
                }
            });
        }));

        let output = self.0.process(cmd).await;

        Ok(JsValue::from_serde(&output)?)
    }
}
