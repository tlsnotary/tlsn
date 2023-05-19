use std::{
    collections::HashSet,
    sync::{Arc, Weak},
};

use async_trait::async_trait;
use futures::{
    stream::{SplitSink, SplitStream},
    StreamExt, TryFutureExt,
};

use mpc_circuits::{
    types::{StaticValueType, Value, ValueType},
    Circuit,
};
use mpc_core::value::ValueRef;
use mpc_garble_core::{encoding_state::Active, msg::GarbleMessage, EncodedValue};
use utils::id::NestedId;
use utils_aio::{mux::MuxChannelControl, Channel};

use crate::{
    config::Role,
    ot::{VerifiableOTReceiveEncoding, VerifiableOTSendEncoding},
    Decode, DecodeError, DecodePrivate, Execute, ExecutionError, Memory, MemoryError, Prove,
    ProveError, Thread, Verify, VerifyError, Vm, VmError,
};

use super::{
    error::{FinalizationError, PeerEncodingsError},
    DEAPError, DEAP,
};

type ChannelFactory = Box<dyn MuxChannelControl<GarbleMessage> + Send + 'static>;
type GarbleChannel = Box<dyn Channel<GarbleMessage, Error = std::io::Error>>;

/// A DEAP Vm.
pub struct DEAPVm<OTS, OTR> {
    /// The id of the vm.
    id: NestedId,
    /// The role of the vm.
    role: Role,
    /// Channel factory used to create new channels for new threads.
    channel_factory: ChannelFactory,
    /// The OT sender.
    ot_send: Arc<OTS>,
    /// The OT receiver.
    ot_recv: Arc<OTR>,
    /// The duplex channel sink to the peer.
    sink: SplitSink<GarbleChannel, GarbleMessage>,
    /// The duplex channel stream from the peer.
    stream: SplitStream<GarbleChannel>,
    /// The DEAP instance.
    ///
    /// The DEAPVm is the only owner of a strong reference to the instance,
    /// and unwraps it during finalization.
    deap: Option<Arc<DEAP>>,
    /// The set of threads spawned by this vm.
    threads: HashSet<NestedId>,
    /// Whether the instance has been finalized.
    finalized: bool,
}

impl<OTS, OTR> DEAPVm<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding,
    OTR: VerifiableOTReceiveEncoding,
{
    /// Create a new DEAP Vm.
    pub fn new(
        id: &str,
        role: Role,
        encoder_seed: [u8; 32],
        channel: GarbleChannel,
        channel_factory: ChannelFactory,
        ot_send: OTS,
        ot_recv: OTR,
    ) -> Self {
        let (sink, stream) = channel.split();
        Self {
            id: NestedId::new(id),
            role,
            channel_factory,
            ot_send: Arc::new(ot_send),
            ot_recv: Arc::new(ot_recv),
            sink,
            stream,
            deap: Some(Arc::new(DEAP::new(role, encoder_seed))),
            threads: HashSet::default(),
            finalized: false,
        }
    }

    /// Finalizes the DEAP instance.
    pub async fn finalize(&mut self) -> Result<(), DEAPError> {
        if self.finalized {
            return Err(FinalizationError::AlreadyFinalized)?;
        } else {
            self.finalized = true;
        }

        let mut instance =
            Arc::try_unwrap(self.deap.take().expect("instance set until finalization"))
                .expect("vm should have only strong reference");

        instance
            .finalize(&mut self.sink, &mut self.stream, &*self.ot_recv)
            .await
    }
}

#[async_trait]
impl<OTS, OTR> Vm for DEAPVm<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding + Clone + Send + Sync + 'static,
    OTR: VerifiableOTReceiveEncoding + Clone + Send + Sync + 'static,
{
    type Thread = DEAPThread<OTS, OTR>;

    async fn new_thread(&mut self, id: &str) -> Result<DEAPThread<OTS, OTR>, VmError> {
        if self.finalized {
            return Err(VmError::Shutdown);
        }

        let thread_id = self.id.append_string(id);

        if self.threads.contains(&thread_id) {
            return Err(VmError::ThreadAlreadyExists(thread_id.to_string()));
        }

        let channel = self
            .channel_factory
            .get_channel(thread_id.to_string())
            .await?;

        Ok(DEAPThread::new(
            thread_id,
            self.role,
            channel,
            Arc::downgrade(self.deap.as_ref().expect("instance set until finalization")),
            self.ot_send.clone(),
            self.ot_recv.clone(),
        ))
    }
}

/// A DEAP thread.
pub struct DEAPThread<OTS, OTR> {
    /// The thread id.
    _id: NestedId,
    /// The DEAP role of the VM.
    _role: Role,
    /// The current operation id.
    op_id: NestedId,
    /// Reference to the DEAP instance.
    deap: Weak<DEAP>,
    /// OT sender.
    ot_send: Arc<OTS>,
    /// OT receiver.
    ot_recv: Arc<OTR>,
    /// The duplex channel sink to the peer.
    sink: SplitSink<GarbleChannel, GarbleMessage>,
    /// The duplex channel stream from the peer.
    stream: SplitStream<GarbleChannel>,
}

impl<OTS, OTR> DEAPThread<OTS, OTR> {
    fn deap(&self) -> Arc<DEAP> {
        self.deap.upgrade().expect("instance should not be dropped")
    }
}

impl<OTS, OTR> DEAPThread<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding,
    OTR: VerifiableOTReceiveEncoding,
{
    fn new(
        id: NestedId,
        role: Role,
        channel: GarbleChannel,
        deap: Weak<DEAP>,
        ot_send: Arc<OTS>,
        ot_recv: Arc<OTR>,
    ) -> Self {
        let (sink, stream) = channel.split();
        let op_id = id.append_counter();
        Self {
            _id: id,
            _role: role,
            op_id,
            deap,
            ot_send,
            ot_recv,
            sink,
            stream,
        }
    }
}

impl<OTS, OTR> Thread for DEAPThread<OTS, OTR> {}

#[async_trait]
impl<OTS, OTR> Memory for DEAPThread<OTS, OTR> {
    fn new_public_input<T: StaticValueType>(
        &self,
        id: &str,
        value: T,
    ) -> Result<ValueRef, MemoryError> {
        self.deap().new_public_input(id, value)
    }

    fn new_public_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Vec<T>,
    ) -> Result<ValueRef, MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        self.deap().new_public_array_input(id, value)
    }

    fn new_public_input_by_type(&self, id: &str, value: Value) -> Result<ValueRef, MemoryError> {
        self.deap().new_public_input_by_type(id, value)
    }

    fn new_private_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<T>,
    ) -> Result<ValueRef, MemoryError> {
        self.deap().new_private_input(id, value)
    }

    fn new_private_array_input<T: StaticValueType>(
        &self,
        id: &str,
        value: Option<Vec<T>>,
        len: usize,
    ) -> Result<ValueRef, MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        self.deap().new_private_array_input(id, value, len)
    }

    fn new_private_input_by_type(
        &self,
        id: &str,
        ty: &ValueType,
        value: Option<Value>,
    ) -> Result<ValueRef, MemoryError> {
        self.deap().new_private_input_by_type(id, ty, value)
    }

    fn new_output<T: StaticValueType>(&self, id: &str) -> Result<ValueRef, MemoryError> {
        self.deap().new_output::<T>(id)
    }

    fn new_array_output<T: StaticValueType>(
        &self,
        id: &str,
        len: usize,
    ) -> Result<ValueRef, MemoryError>
    where
        Vec<T>: Into<Value>,
    {
        self.deap().new_array_output::<T>(id, len)
    }

    fn new_output_by_type(&self, id: &str, ty: &ValueType) -> Result<ValueRef, MemoryError> {
        self.deap().new_output_by_type(id, ty)
    }

    fn get_value(&self, id: &str) -> Option<ValueRef> {
        self.deap().get_value(id)
    }

    fn get_value_type(&self, id: &str) -> Option<ValueType> {
        self.deap().get_value_type(id)
    }
}

#[async_trait]
impl<OTS, OTR> Execute for DEAPThread<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding + Send + Sync,
    OTR: VerifiableOTReceiveEncoding + Send + Sync,
{
    async fn execute(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ExecutionError> {
        self.deap()
            .execute(
                &self.op_id.increment_in_place().to_string(),
                circ,
                inputs,
                outputs,
                &mut self.sink,
                &mut self.stream,
                &*self.ot_send,
                &*self.ot_recv,
            )
            .map_err(ExecutionError::from)
            .await
    }
}

#[async_trait]
impl<OTS, OTR> Prove for DEAPThread<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding + Send + Sync,
    OTR: VerifiableOTReceiveEncoding + Send + Sync,
{
    async fn prove(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
    ) -> Result<(), ProveError> {
        self.deap()
            .defer_prove(
                &self.op_id.increment_in_place().to_string(),
                circ,
                inputs,
                outputs,
                &mut self.sink,
                &mut self.stream,
                &*self.ot_recv,
            )
            .map_err(ProveError::from)
            .await
    }
}

#[async_trait]
impl<OTS, OTR> Verify for DEAPThread<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding + Send + Sync,
    OTR: VerifiableOTReceiveEncoding + Send + Sync,
{
    async fn verify(
        &mut self,
        circ: Arc<Circuit>,
        inputs: &[ValueRef],
        outputs: &[ValueRef],
        expected_outputs: &[Value],
    ) -> Result<(), VerifyError> {
        self.deap()
            .defer_verify(
                &self.op_id.increment_in_place().to_string(),
                circ,
                inputs,
                outputs,
                expected_outputs,
                &mut self.sink,
                &mut self.stream,
                &*self.ot_send,
            )
            .map_err(VerifyError::from)
            .await
    }
}

#[async_trait]
impl<OTS, OTR> Decode for DEAPThread<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding + Send + Sync,
    OTR: VerifiableOTReceiveEncoding + Send + Sync,
{
    async fn decode(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError> {
        self.deap()
            .decode(
                &self.op_id.increment_in_place().to_string(),
                values,
                &mut self.sink,
                &mut self.stream,
            )
            .map_err(DecodeError::from)
            .await
    }
}

#[async_trait]
impl<OTS, OTR> DecodePrivate for DEAPThread<OTS, OTR>
where
    OTS: VerifiableOTSendEncoding + Send + Sync,
    OTR: VerifiableOTReceiveEncoding + Send + Sync,
{
    async fn decode_private(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError> {
        self.deap()
            .decode_private(
                &self.op_id.increment_in_place().to_string(),
                values,
                &mut self.sink,
                &mut self.stream,
                &*self.ot_send,
                &*self.ot_recv,
            )
            .map_err(DecodeError::from)
            .await
    }

    async fn decode_blind(&mut self, values: &[ValueRef]) -> Result<(), DecodeError> {
        self.deap()
            .decode_blind(
                &self.op_id.increment_in_place().to_string(),
                values,
                &mut self.sink,
                &mut self.stream,
                &*self.ot_send,
                &*self.ot_recv,
            )
            .map_err(DecodeError::from)
            .await
    }

    async fn decode_shared(&mut self, values: &[ValueRef]) -> Result<Vec<Value>, DecodeError> {
        self.deap()
            .decode_shared(
                &self.op_id.increment_in_place().to_string(),
                values,
                &mut self.sink,
                &mut self.stream,
                &*self.ot_send,
                &*self.ot_recv,
            )
            .map_err(DecodeError::from)
            .await
    }
}

/// This trait provides methods to get peer's encodings.
trait PeerEncodings {
    /// Returns the peer's encodings of the provided values.
    ///
    /// # Errors
    ///
    /// Returns an error if the value is not found or its encoding is not available.
    fn get_peer_encodings(
        &self,
        value_ids: &[&str],
    ) -> Result<Vec<EncodedValue<Active>>, PeerEncodingsError>;
}

impl<OTS, OTR> PeerEncodings for DEAPVm<OTS, OTR> {
    fn get_peer_encodings(
        &self,
        value_ids: &[&str],
    ) -> Result<Vec<EncodedValue<Active>>, PeerEncodingsError> {
        if self.finalized {
            return Err(PeerEncodingsError::AlreadyFinalized);
        }

        let deap = self.deap.as_ref().expect("instance set until finalization");

        value_ids
            .iter()
            .map(|id| {
                // get reference by id
                let value_ref = match deap.get_value(id) {
                    Some(v) => v,
                    None => return Err(PeerEncodingsError::ValueIdNotFound(id.to_string())),
                };
                // get encoding by reference
                match deap.ev().get_encoding(&value_ref) {
                    Some(e) => Ok(e),
                    None => Err(PeerEncodingsError::EncodingNotAvailable(value_ref)),
                }
            })
            .collect::<Result<Vec<_>, PeerEncodingsError>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use mpc_circuits::circuits::AES128;

    use crate::protocol::deap::mock::create_mock_deap_vm;

    use core::{future::Future, pin::Pin};
    use mpc_core::Block;
    use mpc_ot::mock::{MockOTReceiver, MockOTSender};
    use rstest::{fixture, rstest};

    // Leader and follower VMs in a set up state and the futures which need to be awaited
    // to trigger circuit execution.
    struct VmFixture {
        leader_vm: DEAPVm<MockOTSender<Block>, MockOTReceiver<Block>>,
        leader_fut: Pin<Box<dyn Future<Output = Vec<Value>>>>,
        follower_vm: DEAPVm<MockOTSender<Block>, MockOTReceiver<Block>>,
        follower_fut: Pin<Box<dyn Future<Output = Vec<Value>>>>,
    }

    // Sets up leader and follower VMs.
    #[fixture]
    async fn set_up_vms() -> VmFixture {
        let (mut leader_vm, mut follower_vm) = create_mock_deap_vm("test_vm").await;

        let mut leader_thread = leader_vm.new_thread("test_thread").await.unwrap();
        let mut follower_thread = follower_vm.new_thread("test_thread").await.unwrap();

        let key = [42u8; 16];
        let msg = [69u8; 16];

        let leader_fut = {
            let key_ref = leader_thread
                .new_private_input::<[u8; 16]>("key", Some(key))
                .unwrap();
            let msg_ref = leader_thread
                .new_private_input::<[u8; 16]>("msg", None)
                .unwrap();
            let ciphertext_ref = leader_thread.new_output::<[u8; 16]>("ciphertext").unwrap();

            async move {
                leader_thread
                    .execute(
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                leader_thread.decode(&[ciphertext_ref]).await.unwrap()
            }
        };

        let follower_fut = {
            let key_ref = follower_thread
                .new_private_input::<[u8; 16]>("key", None)
                .unwrap();
            let msg_ref = follower_thread
                .new_private_input::<[u8; 16]>("msg", Some(msg))
                .unwrap();
            let ciphertext_ref = follower_thread
                .new_output::<[u8; 16]>("ciphertext")
                .unwrap();

            async move {
                follower_thread
                    .execute(
                        AES128.clone(),
                        &[key_ref, msg_ref],
                        &[ciphertext_ref.clone()],
                    )
                    .await
                    .unwrap();

                follower_thread.decode(&[ciphertext_ref]).await.unwrap()
            }
        };

        VmFixture {
            leader_vm,
            leader_fut: Box::pin(leader_fut),
            follower_vm,
            follower_fut: Box::pin(follower_fut),
        }
    }

    #[rstest]
    #[tokio::test]
    async fn test_vm(set_up_vms: impl Future<Output = VmFixture>) {
        let VmFixture {
            mut leader_vm,
            leader_fut,
            mut follower_vm,
            follower_fut,
        } = set_up_vms.await;

        let (leader_result, follower_result) = futures::join!(leader_fut, follower_fut);

        assert_eq!(leader_result, follower_result);

        let (leader_result, follower_result) =
            futures::join!(leader_vm.finalize(), follower_vm.finalize());

        leader_result.unwrap();
        follower_result.unwrap();
    }

    #[rstest]
    #[tokio::test]
    async fn test_peer_encodings(set_up_vms: impl Future<Output = VmFixture>) {
        let VmFixture {
            mut leader_vm,
            leader_fut,
            mut follower_vm,
            follower_fut,
        } = set_up_vms.await;

        // Encodings are not yet available because the circuit hasn't yet been executed
        let err = leader_vm.get_peer_encodings(&["msg"]).unwrap_err();
        assert!(matches!(err, PeerEncodingsError::EncodingNotAvailable(_)));

        // Execute the circuits
        _ = futures::join!(leader_fut, follower_fut);

        // Encodings must be available now
        assert!(leader_vm
            .get_peer_encodings(&["msg", "key", "ciphertext"])
            .is_ok());

        // A non-existent value id will cause an error
        let err = leader_vm
            .get_peer_encodings(&["msg", "random_id"])
            .unwrap_err();
        assert!(matches!(err, PeerEncodingsError::ValueIdNotFound(_)));

        // Trying to get encodings after finalization will cause an error
        _ = futures::join!(leader_vm.finalize(), follower_vm.finalize());
        let err = leader_vm.get_peer_encodings(&["msg"]).unwrap_err();
        assert!(matches!(err, PeerEncodingsError::AlreadyFinalized));
    }
}
