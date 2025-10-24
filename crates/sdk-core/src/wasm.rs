use std::{
    sync::{Arc, Mutex},
    task::Poll,
};

use crate::{
    Binary, Error,
    instance::{Instance, InstanceId},
};

pub struct WasmId(pub usize);

pub trait WasmRuntime {
    fn load(&mut self, bin: &Binary) -> Result<WasmId, Error>;

    fn instantiate(
        &mut self,
        id: WasmId,
        instance: Arc<Mutex<Instance>>,
        arg: &[u8],
    ) -> Result<InstanceId, Error>;

    fn poll(&mut self, id: InstanceId) -> Result<Poll<Result<Vec<u8>, String>>, Error>;
}
