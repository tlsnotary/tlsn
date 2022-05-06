use super::PointAdditionError;
use futures_util::{Sink, SinkExt, Stream, StreamExt};
use mpc_core::point_addition::{master, MasterCore, PointAdditionMessage, SecretShare};
use p256::EncodedPoint;
use std::io::Error as IOError;
use std::io::ErrorKind;
use tracing::{instrument, trace};

pub struct PointAdditionMaster<S> {
    stream: S,
}

impl<
        S: Sink<PointAdditionMessage> + Stream<Item = Result<PointAdditionMessage, E>> + Send + Unpin,
        E: std::fmt::Debug,
    > PointAdditionMaster<S>
where
    PointAdditionError: From<<S as Sink<PointAdditionMessage>>::Error>,
    PointAdditionError: From<E>,
{
    pub fn new(stream: S) -> Self {
        Self { stream }
    }

    #[instrument(skip(self, point))]
    pub async fn run(&mut self, point: &EncodedPoint) -> Result<SecretShare, PointAdditionError> {
        let mut master = master::PointAdditionMaster::new(point);

        // Step 1
        let message = master.next(None).unwrap().unwrap();
        trace!("Sending M1");
        self.stream.send(message).await?;
        let slave_message = match self.stream.next().await {
            Some(Ok(PointAdditionMessage::S1(m))) => PointAdditionMessage::S1(m),
            Some(Ok(m)) => return Err(PointAdditionError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received S1");

        // Step 2
        let message = master.next(Some(slave_message)).unwrap().unwrap();
        trace!("Sending M2");
        self.stream.send(message).await?;
        let slave_message = match self.stream.next().await {
            Some(Ok(PointAdditionMessage::S2(m))) => PointAdditionMessage::S2(m),
            Some(Ok(m)) => return Err(PointAdditionError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received S2");

        // Step 3
        let message = master.next(Some(slave_message)).unwrap().unwrap();
        trace!("Sending M3");
        self.stream.send(message).await?;
        let slave_message = match self.stream.next().await {
            Some(Ok(PointAdditionMessage::S3(m))) => PointAdditionMessage::S3(m),
            Some(Ok(m)) => return Err(PointAdditionError::Unexpected(m)),
            Some(Err(e)) => return Err(e)?,
            None => return Err(IOError::new(ErrorKind::UnexpectedEof, ""))?,
        };
        trace!("Received S3");

        // Complete
        master.next(Some(slave_message)).unwrap();

        Ok(master.get_secret())
    }
}
