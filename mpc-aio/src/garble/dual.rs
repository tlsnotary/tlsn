use futures::{SinkExt, StreamExt};
use rand::thread_rng;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::Framed;
use utils_aio::expected_msg;

use crate::garble::Error;
use mpc_circuits::{Circuit, InputValue, OutputValue};
use mpc_core::{
    garble::{
        exec::{
            DualExFollower as FollowerCore, DualExLeader as LeaderCore, OutputCheck, OutputCommit,
        },
        Delta, GarbledCircuit, InputLabels, WireLabelPair,
    },
    msgs::garble::GarbleMessage,
    proto::garble::Message as ProtoMessage,
};
use utils_aio::codec::ProstCodecDelimited;

use super::{WireLabelReceiver, WireLabelSender};

pub struct DualExLeader<S> {
    stream: Framed<S, ProstCodecDelimited<GarbleMessage, ProtoMessage>>,
    circ: Arc<Circuit>,
    label_send: Box<dyn WireLabelSender>,
    label_receive: Box<dyn WireLabelReceiver>,
}
pub struct DualExFollower<S> {
    stream: Framed<S, ProstCodecDelimited<GarbleMessage, ProtoMessage>>,
    circ: Arc<Circuit>,
    label_send: Box<dyn WireLabelSender>,
    label_receive: Box<dyn WireLabelReceiver>,
}

impl<S> DualExLeader<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        stream: S,
        circ: Arc<Circuit>,
        label_send: Box<dyn WireLabelSender>,
        label_receive: Box<dyn WireLabelReceiver>,
    ) -> Self {
        Self {
            stream: Framed::new(
                stream,
                ProstCodecDelimited::<GarbleMessage, ProtoMessage>::default(),
            ),
            circ,
            label_send,
            label_receive,
        }
    }

    pub async fn execute(
        mut self,
        inputs: &[InputValue],
        input_labels: Option<(Vec<InputLabels<WireLabelPair>>, Delta)>,
    ) -> Result<Vec<OutputValue>, Error> {
        let core = LeaderCore::new(self.circ.clone());

        let (input_labels, delta) = match input_labels {
            Some((input_labels, delta)) => (input_labels, delta),
            None => InputLabels::generate(&mut thread_rng(), &self.circ, None),
        };

        let (my_gc, core) = core.garble(inputs, &input_labels, delta)?;
        self.stream
            .send(GarbleMessage::GarbledCircuit(my_gc.into()))
            .await?;

        let my_input_ids: Vec<usize> = inputs.iter().map(|input| input.id()).collect();
        let (my_labels, their_labels): (Vec<InputLabels<_>>, Vec<InputLabels<_>>) = input_labels
            .into_iter()
            .partition(|label| my_input_ids.contains(&label.id()));

        self.label_send.send(&their_labels).await?;

        let their_gc = expected_msg!(self.stream, GarbleMessage::GarbledCircuit)
            .map_err(|msg| Error::UnexpectedMessage(msg))?;

        let their_gc = GarbledCircuit::from_msg(self.circ.clone(), their_gc)?;

        let my_input_labels = self.label_receive.receive(&inputs).await?;

        let (commit, core) = core.evaluate(&their_gc, &my_input_labels)?.commit();

        self.stream
            .send(GarbleMessage::OutputCommit(commit.into()))
            .await?;

        let their_check = expected_msg!(self.stream, GarbleMessage::OutputCheck)
            .map_err(|msg| Error::UnexpectedMessage(msg))?;

        let their_check = OutputCheck::from_msg(their_check)?;

        let (check, core) = core.check(their_check)?.reveal();

        self.stream
            .send(GarbleMessage::OutputCheck(check.into()))
            .await?;

        Ok(core.decode()?)
    }
}

impl<S> DualExFollower<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(
        stream: S,
        circ: Arc<Circuit>,
        label_send: Box<dyn WireLabelSender>,
        label_receive: Box<dyn WireLabelReceiver>,
    ) -> Self {
        Self {
            stream: Framed::new(
                stream,
                ProstCodecDelimited::<GarbleMessage, ProtoMessage>::default(),
            ),
            circ,
            label_send,
            label_receive,
        }
    }

    pub async fn execute(
        mut self,
        inputs: &[InputValue],
        input_labels: Option<(Vec<InputLabels<WireLabelPair>>, Delta)>,
    ) -> Result<Vec<OutputValue>, Error> {
        let core = FollowerCore::new(self.circ.clone());

        let (input_labels, delta) = match input_labels {
            Some((input_labels, delta)) => (input_labels, delta),
            None => InputLabels::generate(&mut thread_rng(), &self.circ, None),
        };

        let (my_gc, core) = core.garble(inputs, &input_labels, delta)?;
        self.stream
            .send(GarbleMessage::GarbledCircuit(my_gc.into()))
            .await?;

        let my_input_ids: Vec<usize> = inputs.iter().map(|input| input.id()).collect();
        let (my_labels, their_labels): (Vec<InputLabels<_>>, Vec<InputLabels<_>>) = input_labels
            .into_iter()
            .partition(|label| my_input_ids.contains(&label.id()));

        self.label_send.send(&their_labels).await?;

        let their_gc = expected_msg!(self.stream, GarbleMessage::GarbledCircuit)
            .map_err(|msg| Error::UnexpectedMessage(msg))?;

        let their_gc = GarbledCircuit::from_msg(self.circ.clone(), their_gc)?;

        let my_input_labels = self.label_receive.receive(&inputs).await?;

        let their_commit = expected_msg!(self.stream, GarbleMessage::OutputCommit)
            .map_err(|msg| Error::UnexpectedMessage(msg))?;

        let their_commit = OutputCommit::from_msg(their_commit)?;

        let (check, core) = core
            .evaluate(&their_gc, &my_input_labels)?
            .reveal(their_commit);

        self.stream
            .send(GarbleMessage::OutputCheck(check.into()))
            .await?;

        let their_check = expected_msg!(self.stream, GarbleMessage::OutputCheck)
            .map_err(|msg| Error::UnexpectedMessage(msg))?;

        let their_check = OutputCheck::from_msg(their_check)?;

        let core = core.check(their_check)?;

        Ok(core.decode()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::garble::{MockWireLabelReceiver, MockWireLabelSender};
    use mpc_circuits::{Circuit, ADDER_64};

    #[tokio::test]
    async fn test() {
        let (ldr_stream, flwr_stream) = tokio::net::UnixStream::pair().unwrap();
        let circ = Arc::new(Circuit::load_bytes(ADDER_64).unwrap());

        let v = vec![vec![true], vec![false; 63]].concat();

        let ldr_input = circ.input(0).unwrap().to_value(&v).unwrap();
        let flwr_input = circ.input(1).unwrap().to_value(&v).unwrap();

        let (ldr_labels, ldr_delta) = InputLabels::generate(&mut thread_rng(), &circ, None);
        let (flwr_labels, flwr_delta) = InputLabels::generate(&mut thread_rng(), &circ, None);

        let mut ldr_label_sender = MockWireLabelSender::new();
        ldr_label_sender.expect_send().returning(|_| Ok(()));

        let mut flwr_label_sender = MockWireLabelSender::new();
        flwr_label_sender.expect_send().returning(|_| Ok(()));

        let mut ldr_label_receiver = MockWireLabelReceiver::new();
        let flwr_labels_clone = flwr_labels.clone();
        ldr_label_receiver
            .expect_receive()
            .return_once(move |value| {
                Ok(vec![flwr_labels_clone[0]
                    .clone()
                    .select(&value[0])
                    .unwrap()])
            });

        let mut flwr_label_receiver = MockWireLabelReceiver::new();
        let ldr_labels_clone = ldr_labels.clone();
        flwr_label_receiver
            .expect_receive()
            .return_once(move |value| Ok(vec![ldr_labels_clone[1].select(&value[0]).unwrap()]));

        let ldr = DualExLeader::new(
            ldr_stream,
            circ.clone(),
            Box::new(ldr_label_sender),
            Box::new(ldr_label_receiver),
        );

        let flwr = DualExFollower::new(
            flwr_stream,
            circ.clone(),
            Box::new(flwr_label_sender),
            Box::new(flwr_label_receiver),
        );

        let ldr_task = ldr.execute(&[ldr_input], Some((ldr_labels, ldr_delta)));
        let flwr_task = flwr.execute(&[flwr_input], Some((flwr_labels, flwr_delta)));

        let (ldr_result, flwr_result) =
            tokio::join!(tokio::spawn(ldr_task), tokio::spawn(flwr_task),);

        let ldr_out = ldr_result.unwrap().unwrap();
        let flwr_out = flwr_result.unwrap().unwrap();

        assert_eq!(ldr_out, flwr_out);
    }
}
