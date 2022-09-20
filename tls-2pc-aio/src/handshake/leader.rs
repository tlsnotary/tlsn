use std::sync::Arc;

use super::{PRFChannel, PRFError};
use futures::{SinkExt, StreamExt};
use mpc_aio::protocol::{
    garble::{Execute, GCError},
    point_addition::{P256SecretShare, PointAddition2PC},
};
use mpc_circuits::Circuit;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::{thread_rng, Rng};
use tls_2pc_core::{
    prf::{self as core, leader_state as state, PRFMessage},
    CIRCUIT_1, CIRCUIT_2,
};

pub struct PRFLeader<G, P>
where
    G: Execute + Send,
    P: PointAddition2PC + Send,
{
    channel: PRFChannel,
    gc_exec: G,
    point_addition: P,
}

impl<G, P> PRFLeader<G, P>
where
    G: Execute + Send,
    P: PointAddition2PC + Send,
{
    pub fn new(channel: PRFChannel, gc_exec: G, point_addition: P) -> Self {
        Self {
            channel,
            gc_exec,
            point_addition,
        }
    }

    async fn c1(&mut self, secret_share: P256SecretShare) -> Result<[u32; 8], PRFError> {
        // todo lazy static load circuits
        let circ = Arc::new(Circuit::load_bytes(CIRCUIT_1).expect("Circuit 1 should deserialize"));
        let input_pms_share = circ
            .input(0)
            .expect("Circuit 1 should have input 0")
            .to_value(secret_share.as_bytes().to_vec())
            .expect("P256SecretShare should always be 32 bytes");

        let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
        let input_mask = circ
            .input(2)
            .expect("Circuit 1 should have input 2")
            .to_value(mask.clone())
            .expect("Mask should always be 32 bytes");

        let inputs = vec![input_pms_share, input_mask];
        let out = self
            .gc_exec
            .execute(circ, &inputs)
            .await?
            .decode()
            .map_err(|e| GCError::from(e))?;

        // todo make this less gross
        let masked_inner_hash_state = if let mpc_circuits::Value::Bytes(v) = c1_out
            .get(0)
            .expect("Circuit 1 should have output 0")
            .value()
        {
            v
        } else {
            panic!("Circuit 1 output 0 should be 32 bytes")
        };

        let inner_hash_state = masked_inner_hash_state
            .iter()
            .zip(mask.iter())
            .map(|(v, m)| v ^ m)
            .rev()
            .collect::<Vec<u8>>();

        let inner_hash_state: [u32; 8] = inner_hash_state
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<u32>>()
            .try_into()
            .expect("Circuit 1 output 0 should be 32 bytes");

        Ok(inner_hash_state)
    }

    async fn c2(&mut self, p1_inner_hash: P256SecretShare) -> Result<[u32; 8], PRFError> {
        // todo lazy static load circuits
        let c2 = Arc::new(Circuit::load_bytes(CIRCUIT_2).expect("Circuit 2 should deserialize"));
        let input_pms_share = c2
            .input(0)
            .expect("Circuit 1 should have input 0")
            .to_value(p1_inner_hash.as_bytes().to_vec())
            .expect("P256SecretShare should always be 32 bytes");

        let mask: Vec<u8> = thread_rng().gen::<[u8; 32]>().to_vec();
        let input_mask = c2
            .input(2)
            .expect("Circuit 1 should have input 2")
            .to_value(mask.clone())
            .expect("Mask should always be 32 bytes");

        let inputs = vec![input_pms_share, input_mask];
        let out = self
            .gc_exec
            .execute(c2, &c1_inputs)
            .await?
            .decode()
            .map_err(|e| GCError::from(e))?;

        // todo make this less gross
        let masked_inner_hash_state = if let mpc_circuits::Value::Bytes(v) = c1_out
            .get(0)
            .expect("Circuit 1 should have output 0")
            .value()
        {
            v
        } else {
            panic!("Circuit 1 output 0 should be 32 bytes")
        };

        let inner_hash_state = masked_inner_hash_state
            .iter()
            .zip(mask.iter())
            .map(|(v, m)| v ^ m)
            .rev()
            .collect::<Vec<u8>>();

        let inner_hash_state: [u32; 8] = inner_hash_state
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
            .collect::<Vec<u32>>()
            .try_into()
            .expect("Circuit 1 output 0 should be 32 bytes");

        Ok(inner_hash_state)
    }

    pub async fn handshake(
        &mut self,
        client_random: [u8; 32],
        server_random: [u8; 32],
        private_key: p256::SecretKey,
        server_pk: p256::PublicKey,
    ) -> Result<(), PRFError> {
        let point =
            (&server_pk.to_projective() * &private_key.to_nonzero_scalar()).to_encoded_point(false);

        // Compute secret share using PointAdditon2PC protocol
        let secret_share = self.point_addition.add(&point).await?;
        // Compute HMAC inner hash state using garbled circuits in DE mode
        let inner_hash_state = self.c1(secret_share).await?;
        let core = core::PRFLeader::new(client_random, server_random, inner_hash_state);

        let (msg, core) = core.next();
        self.channel.send(PRFMessage::LeaderMs1(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerMs1(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderMs2(msg)).await?;

        let msg = match self.channel.next().await {
            Some(PRFMessage::FollowerMs2(msg)) => msg,
            Some(m) => return Err(PRFError::UnexpectedMessage(m)),
            None => {
                return Err(PRFError::from(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "stream closed unexpectedly",
                )))
            }
        };

        let (msg, core) = core.next(msg);
        self.channel.send(PRFMessage::LeaderMs3(msg)).await?;

        let p1_inner_hash = core.p1_inner_hash();

        todo!()
    }
}
