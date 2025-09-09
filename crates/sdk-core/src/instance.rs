use std::{
    collections::HashMap,
    task::{Context as StdContext, Poll},
};

use crate::{
    Error, IoProvider,
    io::{IoId, IoInstance},
    prover::{ProverId, ProverInstance},
    verifier::{VerifierId, VerifierInstance},
};

#[derive(Default)]
pub struct Instance {
    pub state: State,
    pub cx: Context,
}

pub struct Context {
    pub waker: Waker,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            waker: Waker::new(),
        }
    }
}

pub struct Waker {
    wants_wake: bool,
    wants_call: bool,
}

impl Waker {
    pub fn new() -> Self {
        Self {
            wants_wake: false,
            wants_call: true,
        }
    }

    pub fn set_wake(&mut self) {
        self.wants_wake = true;
    }

    pub fn clear_wake(&mut self) {
        self.wants_wake = false;
    }

    pub fn set_call(&mut self) {
        self.wants_call = true;
    }

    pub fn clear_call(&mut self) {
        self.wants_call = false;
    }

    pub fn wants_wake(&self) -> bool {
        self.wants_wake
    }

    pub fn wants_call(&self) -> bool {
        self.wants_call
    }
}

/// Plugin instance.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct InstanceId(pub usize);

#[derive(Default)]
pub struct State {
    provers: HashMap<ProverId, ProverInstance>,
    verifiers: HashMap<VerifierId, VerifierInstance>,
}

impl State {
    pub fn new() -> Self {
        Self {
            provers: HashMap::new(),
            verifiers: HashMap::new(),
        }
    }

    pub fn new_prover(&mut self, config: Vec<u8>) -> Result<ProverId, Error> {
        let instance = ProverInstance::new(config)?;

        let id = ProverId(self.provers.len());
        self.provers.insert(id, instance);

        Ok(id)
    }

    pub fn new_verifier(&mut self, config: Vec<u8>) -> Result<VerifierId, Error> {
        let instance = VerifierInstance::new(config)?;

        let id = VerifierId(self.verifiers.len());
        self.verifiers.insert(id, instance);

        Ok(id)
    }

    pub fn get_prover_mut(&mut self, id: ProverId) -> Result<&mut ProverInstance, Error> {
        self.provers.get_mut(&id).ok_or_else(|| todo!())
    }

    pub fn get_io_mut(&mut self, id: IoId) -> Result<&mut IoInstance, Error> {
        self.get_prover_mut(ProverId(id.0))?
            .io_mut()
            .ok_or_else(|| todo!())
    }

    pub fn get_verifier_mut(&mut self, id: VerifierId) -> Result<&mut VerifierInstance, Error> {
        self.verifiers.get_mut(&id).ok_or_else(|| todo!())
    }

    pub fn poll(
        &mut self,
        cx_std: &mut StdContext<'_>,
        cx: &mut Context,
        io: &mut impl IoProvider,
    ) -> Poll<Result<(), Error>> {
        let mut ready = Vec::new();
        for (&id, prover) in self.provers.iter_mut() {
            if let Poll::Ready(res) = prover.poll(cx_std, cx, io) {
                res.unwrap();
                ready.push(id);
            }
        }

        for id in ready {
            self.provers.remove(&id);
        }

        let mut ready = Vec::new();
        for (&id, verifier) in self.verifiers.iter_mut() {
            if let Poll::Ready(res) = verifier.poll(cx_std, cx, io) {
                res.unwrap();
                ready.push(id);
            }
        }

        for id in ready {
            self.verifiers.remove(&id);
        }

        if self.provers.is_empty() && self.verifiers.is_empty() {
            return Poll::Ready(Ok(()));
        } else {
            Poll::Pending
        }
    }
}
