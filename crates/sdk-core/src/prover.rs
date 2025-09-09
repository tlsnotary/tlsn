use std::{
    pin::Pin,
    task::{Context as StdContext, Poll},
};

use futures::FutureExt;
use tlsn::{
    config::ProverConfig,
    connection::ServerName,
    prover::{ProveConfig, Prover, ProverFuture, ProverOutput, TlsConnection, state},
    transcript::{TlsTranscript, Transcript},
};

use crate::{Error, IoProvider, instance::Context, io::IoInstance};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct ProverId(pub usize);

pub struct ProverInstance {
    state: State,
    server_name: ServerName,
    server_io: Option<IoInstance>,
    wants_state_update: bool,
}

impl ProverInstance {
    pub fn new(config: Vec<u8>) -> Result<Self, Error> {
        println!("prover new");
        let config: ProverConfig = bincode::deserialize(&config).unwrap();

        let server_name = config.server_name().clone();
        let prover = Prover::new(config);

        Ok(Self {
            state: State::Init(prover),
            server_name,
            server_io: None,
            wants_state_update: false,
        })
    }

    pub fn io_mut(&mut self) -> Option<&mut IoInstance> {
        self.server_io.as_mut()
    }

    pub fn setup(&mut self, cx: &mut Context) -> Result<Poll<()>, Error> {
        match self.state.take() {
            State::Init(prover) => {
                self.state = State::Preprocess(prover);
            }
            State::Preprocess(prover) => {
                self.state = State::Preprocess(prover);
            }
            State::Preprocessing(fut) => {
                self.state = State::Preprocessing(fut);
            }
            State::Setup(prover) => {
                self.state = State::Setup(prover);
                return Ok(Poll::Ready(()));
            }
            state => todo!(),
        };

        self.wants_state_update = true;
        cx.waker.set_wake();

        Ok(Poll::Pending)
    }

    pub fn connect(&mut self, cx: &mut Context) -> Result<Poll<()>, Error> {
        match self.state.take() {
            State::Setup(prover) => {
                self.state = State::Connect(prover);
            }
            State::Connect(prover) => {
                self.state = State::Connect(prover);
            }
            State::Connecting(fut) => {
                self.state = State::Connecting(fut);
            }
            State::Online(fut) => {
                self.state = State::Online(fut);

                return Ok(Poll::Ready(()));
            }
            state => todo!(),
        }

        self.wants_state_update = true;
        cx.waker.set_wake();

        Ok(Poll::Pending)
    }

    pub fn finish_commit(
        &mut self,
        cx: &mut Context,
    ) -> Result<Poll<(TlsTranscript, Transcript)>, Error> {
        match self.state.take() {
            State::Online(fut) => {
                self.state = State::Online(fut);
            }
            State::FinishCommit(prover) => {
                let tls_transcript = prover.tls_transcript().clone();
                let transcript = prover.transcript().clone();

                self.state = State::Committed(prover);

                return Ok(Poll::Ready((tls_transcript, transcript)));
            }
            state => todo!(),
        }

        self.wants_state_update = true;
        cx.waker.set_wake();

        Ok(Poll::Pending)
    }

    pub fn prove(&mut self, config: ProveConfig) -> Result<(), Error> {
        match self.state.take() {
            State::Committed(prover) => {
                self.state = State::StartProve(prover, config);
            }
            state => todo!(),
        }

        Ok(())
    }

    pub fn finish_prove(&mut self, cx: &mut Context) -> Result<Poll<ProverOutput>, Error> {
        match self.state.take() {
            State::StartProve(prover, config) => {
                self.state = State::StartProve(prover, config);
            }
            State::Proving(fut) => {
                self.state = State::Proving(fut);
            }
            State::FinishProve(prover, output) => {
                self.state = State::Committed(prover);

                return Ok(Poll::Ready(output));
            }
            state => todo!(),
        }

        self.wants_state_update = true;
        cx.waker.set_wake();

        Ok(Poll::Pending)
    }

    pub fn close(&mut self, cx: &mut Context) -> Result<Poll<()>, Error> {
        match self.state.take() {
            State::Committed(prover) => {
                self.state = State::Close(prover);
            }
            State::Close(prover) => {
                self.state = State::Close(prover);
            }
            State::Closing(fut) => {
                self.state = State::Closing(fut);
            }
            State::FinishClose => {
                self.state = State::Done;

                return Ok(Poll::Ready(()));
            }
            state => {
                dbg!(state);
                todo!()
            }
        }

        self.wants_state_update = true;
        cx.waker.set_wake();

        Ok(Poll::Pending)
    }

    pub fn poll(
        &mut self,
        cx_std: &mut StdContext<'_>,
        cx: &mut Context,
        io: &mut impl IoProvider,
    ) -> Poll<Result<(), Error>> {
        if let Some(io) = self.server_io.as_mut() {
            if let Poll::Ready(res) = io.poll(cx_std, cx) {
                res?;
            }
        }

        match self.state.take() {
            State::Init(prover) => {
                self.state = State::Init(prover);
            }
            State::Preprocess(prover) => {
                let io_fut = io.connect_peer();
                self.state = State::Preprocessing(Box::pin(async move {
                    prover
                        .setup(io_fut.await.unwrap())
                        .await
                        .map_err(|_| todo!())
                }));

                return self.poll(cx_std, cx, io);
            }
            State::Preprocessing(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    let prover = res.unwrap();

                    self.state = State::Setup(prover);
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }

                    println!("prover setup");
                } else {
                    self.state = State::Preprocessing(fut);
                }
            }
            State::Setup(prover) => {
                self.state = State::Setup(prover);
            }
            State::Connect(prover) => {
                let io_fut = io.connect_server(&self.server_name);
                self.state = State::Connecting(Box::pin(async move {
                    prover
                        .connect(io_fut.await.unwrap())
                        .await
                        .map_err(|_| todo!())
                }));

                println!("prover connect");

                return self.poll(cx_std, cx, io);
            }
            State::Connecting(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    let (conn, fut) = res.unwrap();

                    self.state = State::Online(fut);
                    self.server_io = Some(IoInstance::new(conn));
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }

                    println!("prover online");

                    return self.poll(cx_std, cx, io);
                } else {
                    self.state = State::Connecting(fut);
                }
            }
            State::Online(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    let prover = res.unwrap();

                    self.state = State::FinishCommit(prover);
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }

                    println!("prover committed");
                } else {
                    self.state = State::Online(fut);
                }
            }
            State::FinishCommit(prover) => {
                self.state = State::FinishCommit(prover);
            }
            State::Committed(prover) => {
                self.state = State::Committed(prover);
            }
            State::StartProve(mut prover, config) => {
                self.state = State::Proving(Box::pin(async move {
                    let output = prover.prove(&config).await.map_err(|_| todo!())?;

                    Ok((prover, output))
                }));

                return self.poll(cx_std, cx, io);
            }
            State::Proving(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    let (prover, output) = res.unwrap();

                    self.state = State::FinishProve(prover, output);
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }
                } else {
                    self.state = State::Proving(fut);
                }
            }
            State::FinishProve(prover, output) => {
                self.state = State::FinishProve(prover, output);
            }
            State::Close(prover) => {
                self.state = State::Closing(Box::pin(async move {
                    prover.close().await.map_err(|_| todo!())
                }));

                return self.poll(cx_std, cx, io);
            }
            State::Closing(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    res?;

                    println!("prover closed");

                    self.state = State::FinishClose;
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }
                } else {
                    self.state = State::Closing(fut);
                }
            }
            State::FinishClose => {
                self.state = State::FinishClose;
            }
            State::Done => {
                self.state = State::Done;

                return Poll::Ready(Ok(()));
            }
            State::Error => todo!(),
        }

        Poll::Pending
    }
}

enum State {
    Init(Prover<state::Initialized>),
    Preprocess(Prover<state::Initialized>),
    Preprocessing(Pin<Box<dyn Future<Output = Result<Prover<state::Setup>, Error>>>>),
    Setup(Prover<state::Setup>),
    Connect(Prover<state::Setup>),
    Connecting(Pin<Box<dyn Future<Output = Result<(TlsConnection, ProverFuture), Error>>>>),
    Online(ProverFuture),
    FinishCommit(Prover<state::Committed>),
    Committed(Prover<state::Committed>),
    StartProve(Prover<state::Committed>, ProveConfig),
    Proving(Pin<Box<dyn Future<Output = Result<(Prover<state::Committed>, ProverOutput), Error>>>>),
    FinishProve(Prover<state::Committed>, ProverOutput),
    Close(Prover<state::Committed>),
    Closing(Pin<Box<dyn Future<Output = Result<(), Error>>>>),
    FinishClose,
    Done,
    Error,
}

impl State {
    fn take(&mut self) -> Self {
        std::mem::replace(self, Self::Error)
    }
}

impl std::fmt::Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Init(_) => f.debug_tuple("Init").finish_non_exhaustive(),
            Self::Preprocess(_) => f.debug_tuple("Preprocess").finish_non_exhaustive(),
            Self::Preprocessing(_) => f.debug_tuple("Preprocessing").finish_non_exhaustive(),
            Self::Setup(_) => f.debug_tuple("Setup").finish_non_exhaustive(),
            Self::Connect(_) => f.debug_tuple("Connect").finish_non_exhaustive(),
            Self::Connecting(_) => f.debug_tuple("Connecting").finish_non_exhaustive(),
            Self::Online(_) => f.debug_tuple("Online").finish_non_exhaustive(),
            Self::FinishCommit(_) => f.debug_tuple("FinishCommit").finish_non_exhaustive(),
            Self::Committed(_) => f.debug_tuple("Committed").finish_non_exhaustive(),
            Self::StartProve(_, _) => f.debug_tuple("StartProve").finish_non_exhaustive(),
            Self::Proving(_) => f.debug_tuple("Proving").finish_non_exhaustive(),
            Self::FinishProve(_, _) => f.debug_tuple("FinishProve").finish_non_exhaustive(),
            Self::Close(_) => f.debug_tuple("Close").finish_non_exhaustive(),
            Self::Closing(_) => f.debug_tuple("Closing").finish_non_exhaustive(),
            Self::FinishClose => f.write_str("FinishClose"),
            Self::Done => f.write_str("Done"),
            Self::Error => f.write_str("Error"),
        }
    }
}
