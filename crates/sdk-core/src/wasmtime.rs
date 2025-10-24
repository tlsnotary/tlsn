use std::{
    sync::{Arc, Mutex},
    task::Poll,
};

use wasmtime::{
    Engine, Store,
    component::{Component, HasSelf, Linker, Resource},
};

use crate::{
    Error, WasmRuntime,
    instance::{self, Context, InstanceId},
    io::IoId,
    prover::ProverId,
    verifier::VerifierId,
    wasm::WasmId,
};

mod generated {
    wasmtime::component::bindgen!({
        world: "plugin",
        path: "wit/tlsn.wit",
        trappable_imports: true,
        with: {
            "tlsn:tlsn/prove/prover": crate::prover::ProverId,
            "tlsn:tlsn/verify/verifier": crate::verifier::VerifierId,
            "tlsn:tlsn/io/io": crate::io::IoId,
        }
    });
}
use generated::{Plugin, tlsn::tlsn as abi};

struct InstanceState {
    inner: Arc<Mutex<instance::Instance>>,
}

impl abi::io::Host for InstanceState {}
impl abi::io::HostIo for InstanceState {
    fn check_write(
        &mut self,
        self_: Resource<IoId>,
    ) -> Result<abi::io::CheckWriteReturn, wasmtime::Error> {
        let id = self_.rep();

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let io = instance.state.get_io_mut(IoId(id as usize)).unwrap();

        match io.check_write(&mut instance.cx) {
            Poll::Pending => Ok(abi::io::CheckWriteReturn::Pending),
            Poll::Ready(Ok(n)) => Ok(abi::io::CheckWriteReturn::Ready(Ok(n as u32))),
            Poll::Ready(Err(e)) => Ok(abi::io::CheckWriteReturn::Ready(Err(
                abi::io::Error::Other(e.to_string()),
            ))),
        }
    }

    fn write(
        &mut self,
        self_: Resource<IoId>,
        buf: Vec<u8>,
    ) -> Result<Result<(), abi::io::Error>, wasmtime::Error> {
        let id = self_.rep();

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let io = instance.state.get_io_mut(IoId(id as usize)).unwrap();

        Ok(io.write(buf.as_slice()).map_err(|_| todo!()))
    }

    fn close(&mut self, self_: Resource<IoId>) -> Result<abi::io::CloseReturn, wasmtime::Error> {
        let id = self_.rep();

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let io = instance.state.get_io_mut(IoId(id as usize)).unwrap();

        match io.close(&mut instance.cx) {
            Poll::Pending => Ok(abi::io::CloseReturn::Pending),
            Poll::Ready(Ok(())) => Ok(abi::io::CloseReturn::Ready(Ok(()))),
            Poll::Ready(Err(e)) => Ok(abi::io::CloseReturn::Ready(Err(abi::io::Error::Other(
                e.to_string(),
            )))),
        }
    }

    fn read(
        &mut self,
        self_: Resource<IoId>,
        len: u32,
    ) -> Result<abi::io::ReadReturn, wasmtime::Error> {
        let id = self_.rep();

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let io = instance.state.get_io_mut(IoId(id as usize)).unwrap();

        match io.read(len as usize, &mut instance.cx) {
            Poll::Pending => Ok(abi::io::ReadReturn::Pending),
            Poll::Ready(Ok(data)) => Ok(abi::io::ReadReturn::Ready(Ok(data))),
            Poll::Ready(Err(e)) => Ok(abi::io::ReadReturn::Ready(Err(abi::io::Error::Other(
                e.to_string(),
            )))),
        }
    }

    fn drop(&mut self, rep: Resource<IoId>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl abi::prove::Host for InstanceState {}
impl abi::prove::HostProver for InstanceState {
    fn new(&mut self, config: Vec<u8>) -> wasmtime::Result<Resource<ProverId>> {
        let id = self.inner.lock().unwrap().state.new_prover(config).unwrap();

        Ok(Resource::new_own(id.0 as u32))
    }

    fn setup(&mut self, self_: Resource<ProverId>) -> wasmtime::Result<abi::prove::SetupReturn> {
        let id = ProverId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let prover = instance.state.get_prover_mut(id).unwrap();

        if let Poll::Ready(()) = prover.setup(&mut instance.cx).unwrap() {
            Ok(abi::prove::SetupReturn::Ready)
        } else {
            Ok(abi::prove::SetupReturn::Pending)
        }
    }

    fn connect(
        &mut self,
        self_: Resource<ProverId>,
    ) -> wasmtime::Result<abi::prove::ConnectReturn> {
        let id = ProverId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let prover = instance.state.get_prover_mut(id).unwrap();

        if let Poll::Ready(()) = prover.connect(&mut instance.cx).unwrap() {
            Ok(abi::prove::ConnectReturn::Ready(Resource::new_own(
                id.0 as u32,
            )))
        } else {
            Ok(abi::prove::ConnectReturn::Pending)
        }
    }

    fn finish_commit(
        &mut self,
        self_: Resource<ProverId>,
    ) -> wasmtime::Result<abi::prove::CommitReturn> {
        let id = ProverId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let prover = instance.state.get_prover_mut(id).unwrap();

        if let Poll::Ready((tls_transcript, transcript)) =
            prover.finish_commit(&mut instance.cx).unwrap()
        {
            Ok(abi::prove::CommitReturn::Ready(Ok(bincode::serialize(&(
                tls_transcript,
                transcript,
            ))
            .unwrap())))
        } else {
            Ok(abi::prove::CommitReturn::Pending)
        }
    }

    fn prove(&mut self, self_: Resource<ProverId>, config: Vec<u8>) -> wasmtime::Result<()> {
        let config = bincode::deserialize(&config).unwrap();

        let id = ProverId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let prover = instance.state.get_prover_mut(id).unwrap();

        prover.prove(config).unwrap();

        Ok(())
    }

    fn finish_prove(
        &mut self,
        self_: Resource<ProverId>,
    ) -> wasmtime::Result<abi::prove::ProveReturn> {
        let id = ProverId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let prover = instance.state.get_prover_mut(id).unwrap();

        if let Poll::Ready(output) = prover.finish_prove(&mut instance.cx).unwrap() {
            Ok(abi::prove::ProveReturn::Ready(Ok(bincode::serialize(
                &output,
            )
            .unwrap())))
        } else {
            Ok(abi::prove::ProveReturn::Pending)
        }
    }

    fn close(&mut self, self_: Resource<ProverId>) -> wasmtime::Result<abi::prove::CloseReturn> {
        let id = ProverId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let prover = instance.state.get_prover_mut(id).unwrap();

        if let Poll::Ready(()) = prover.close(&mut instance.cx).unwrap() {
            Ok(abi::prove::CloseReturn::Ready)
        } else {
            Ok(abi::prove::CloseReturn::Pending)
        }
    }

    fn drop(&mut self, rep: Resource<ProverId>) -> wasmtime::Result<()> {
        Ok(())
    }
}

impl abi::verify::Host for InstanceState {}
impl abi::verify::HostVerifier for InstanceState {
    fn new(&mut self, config: Vec<u8>) -> wasmtime::Result<Resource<VerifierId>> {
        let id = self
            .inner
            .lock()
            .unwrap()
            .state
            .new_verifier(config)
            .unwrap();

        Ok(Resource::new_own(id.0 as u32))
    }

    fn setup(&mut self, self_: Resource<VerifierId>) -> wasmtime::Result<abi::verify::SetupReturn> {
        let id = VerifierId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let verifier = instance.state.get_verifier_mut(VerifierId(id.0)).unwrap();

        if let Poll::Ready(()) = verifier.setup(&mut instance.cx).unwrap() {
            Ok(abi::verify::SetupReturn::Ready)
        } else {
            Ok(abi::verify::SetupReturn::Pending)
        }
    }

    fn commit(
        &mut self,
        self_: Resource<VerifierId>,
    ) -> wasmtime::Result<abi::verify::CommitReturn> {
        let id = VerifierId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let verifier = instance.state.get_verifier_mut(VerifierId(id.0)).unwrap();

        if let Poll::Ready(tls_transcript) = verifier.commit(&mut instance.cx).unwrap() {
            Ok(abi::verify::CommitReturn::Ready(Ok(bincode::serialize(
                &tls_transcript,
            )
            .unwrap())))
        } else {
            Ok(abi::verify::CommitReturn::Pending)
        }
    }

    fn verify(&mut self, self_: Resource<VerifierId>, config: Vec<u8>) -> wasmtime::Result<()> {
        let config = bincode::deserialize(&config).unwrap();

        let id = VerifierId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let verifier = instance.state.get_verifier_mut(VerifierId(id.0)).unwrap();

        verifier.verify(config).unwrap();

        Ok(())
    }

    fn finish_verify(
        &mut self,
        self_: Resource<VerifierId>,
    ) -> wasmtime::Result<abi::verify::VerifyReturn> {
        let id = VerifierId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let verifier = instance.state.get_verifier_mut(VerifierId(id.0)).unwrap();

        if let Poll::Ready(output) = verifier.finish_verify(&mut instance.cx).unwrap() {
            Ok(abi::verify::VerifyReturn::Ready(Ok(bincode::serialize(
                &output,
            )
            .unwrap())))
        } else {
            Ok(abi::verify::VerifyReturn::Pending)
        }
    }

    fn close(&mut self, self_: Resource<VerifierId>) -> wasmtime::Result<abi::verify::CloseReturn> {
        let id = VerifierId(self_.rep() as usize);

        let mut guard = self.inner.lock().unwrap();
        let instance = &mut (*guard);
        let verifier = instance.state.get_verifier_mut(VerifierId(id.0)).unwrap();

        if let Poll::Ready(()) = verifier.close(&mut instance.cx).unwrap() {
            Ok(abi::verify::CloseReturn::Ready)
        } else {
            Ok(abi::verify::CloseReturn::Pending)
        }
    }

    fn drop(&mut self, rep: Resource<VerifierId>) -> wasmtime::Result<()> {
        Ok(())
    }
}

use crate::Binary;

pub struct Wasmtime {
    engine: Engine,
    components: Vec<Component>,
    instances: Vec<(Plugin, Store<InstanceState>)>,
}

impl Wasmtime {
    pub fn new() -> Self {
        Self {
            engine: Engine::default(),
            components: vec![],
            instances: vec![],
        }
    }
}

impl WasmRuntime for Wasmtime {
    fn load(&mut self, bin: &Binary) -> Result<WasmId, Error> {
        let id = self.components.len();

        let component = Component::from_binary(&self.engine, &bin.0).unwrap();

        self.components.push(component);

        Ok(WasmId(id))
    }

    fn instantiate(
        &mut self,
        id: WasmId,
        instance: Arc<Mutex<instance::Instance>>,
        arg: &[u8],
    ) -> Result<InstanceId, Error> {
        let state = InstanceState { inner: instance };
        let mut store = Store::new(&self.engine, state);
        let mut linker = Linker::new(&self.engine);

        generated::tlsn::tlsn::io::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .unwrap();
        generated::tlsn::tlsn::prove::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .unwrap();
        generated::tlsn::tlsn::verify::add_to_linker::<_, HasSelf<_>>(&mut linker, |state| state)
            .unwrap();

        let component = self.components.get(id.0).unwrap();
        let instance = Plugin::instantiate(&mut store, component, &linker).unwrap();

        instance.call_start(&mut store, arg).unwrap();

        let id = self.instances.len();
        self.instances.push((instance, store));

        Ok(InstanceId(id))
    }

    fn poll(&mut self, id: InstanceId) -> Result<Poll<Result<Vec<u8>, String>>, Error> {
        let (instance, store) = self.instances.get_mut(id.0).unwrap();

        let res = match instance.call_poll(store).unwrap() {
            generated::PollReturn::Pending => Poll::Pending,
            generated::PollReturn::Ready(ret) => Poll::Ready(ret),
        };

        Ok(res)
    }
}
