use std::{
    pin::Pin,
    task::{Context as StdContext, Poll},
};

use futures::FutureExt;
use tlsn::{
    config::{VerifierConfig, VerifyConfig},
    transcript::TlsTranscript,
    verifier::{Verifier, VerifierOutput, state},
};

use crate::{Error, IoProvider, instance::Context};

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash)]
pub struct VerifierId(pub usize);

pub struct VerifierInstance {
    state: State,
    wants_state_update: bool,
}

impl VerifierInstance {
    pub fn new(config: Vec<u8>) -> Result<Self, Error> {
        let config: VerifierConfig = bincode::deserialize(&config).unwrap();

        let verifier = Verifier::new(config);

        Ok(Self {
            state: State::Init(verifier),
            wants_state_update: false,
        })
    }

    pub fn setup(&mut self, cx: &mut Context) -> Result<Poll<()>, Error> {
        match self.state.take() {
            State::Init(verifier) => {
                self.state = State::Preprocess(verifier);
            }
            State::Preprocess(verifier) => {
                self.state = State::Preprocess(verifier);
            }
            State::Preprocessing(fut) => {
                self.state = State::Preprocessing(fut);
            }
            State::Setup(verifier) => {
                self.state = State::Setup(verifier);
                return Ok(Poll::Ready(()));
            }
            state => todo!(),
        };

        self.wants_state_update = true;
        cx.waker.set_wake();

        Ok(Poll::Pending)
    }

    pub fn commit(&mut self, cx: &mut Context) -> Result<Poll<TlsTranscript>, Error> {
        match self.state.take() {
            State::Setup(verifier) => {
                self.state = State::StartCommit(verifier);
            }
            State::StartCommit(verifier) => {
                self.state = State::StartCommit(verifier);
            }
            State::Online(fut) => {
                self.state = State::Online(fut);
            }
            State::FinishCommit(verifier) => {
                let tls_transcript = verifier.tls_transcript().clone();

                self.state = State::Committed(verifier);

                println!("verifier committed");

                return Ok(Poll::Ready(tls_transcript));
            }
            state => todo!(),
        }

        self.wants_state_update = true;
        cx.waker.set_wake();

        Ok(Poll::Pending)
    }

    pub fn verify(&mut self, config: VerifyConfig) -> Result<(), Error> {
        match self.state.take() {
            State::Committed(verifier) => {
                self.state = State::StartVerify(verifier, config);
            }
            State::StartVerify(verifier, config) => {
                self.state = State::StartVerify(verifier, config);
            }
            state => todo!(),
        }

        Ok(())
    }

    pub fn finish_verify(&mut self, cx: &mut Context) -> Result<Poll<VerifierOutput>, Error> {
        match self.state.take() {
            State::StartVerify(verifier, config) => {
                self.state = State::StartVerify(verifier, config);
            }
            State::Verifying(fut) => {
                self.state = State::Verifying(fut);
            }
            State::FinishVerify(verifier, output) => {
                self.state = State::Committed(verifier);

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
            State::Committed(verifier) => {
                self.state = State::Close(verifier);
            }
            State::Close(verifier) => {
                self.state = State::Close(verifier);
            }
            State::Closing(fut) => {
                self.state = State::Closing(fut);
            }
            State::FinishClose => {
                self.state = State::Done;

                println!("verifier closed");

                return Ok(Poll::Ready(()));
            }
            state => todo!(),
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
        match self.state.take() {
            State::Init(verifier) => {
                self.state = State::Init(verifier);
            }
            State::Preprocess(verifier) => {
                let io_fut = io.connect_peer();
                self.state = State::Preprocessing(Box::pin(async move {
                    verifier
                        .setup(io_fut.await.unwrap())
                        .await
                        .map_err(|_| todo!())
                }));

                return self.poll(cx_std, cx, io);
            }
            State::Preprocessing(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    let verifier = res.unwrap();

                    println!("verifier setup");

                    self.state = State::Setup(verifier);
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }
                } else {
                    self.state = State::Preprocessing(fut);
                }
            }
            State::Setup(verifier) => {
                self.state = State::Setup(verifier);
            }
            State::StartCommit(verifier) => {
                self.state = State::Online(Box::pin(async move {
                    verifier.run().await.map_err(|_| todo!())
                }));

                println!("verifier start commit");

                return self.poll(cx_std, cx, io);
            }
            State::Online(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    let verifier = res.unwrap();

                    self.state = State::FinishCommit(verifier);
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }
                    println!("verifier finish commit");
                } else {
                    self.state = State::Online(fut);
                }
            }
            State::FinishCommit(verifier) => {
                self.state = State::FinishCommit(verifier);
            }
            State::Committed(verifier) => {
                self.state = State::Committed(verifier);
            }
            State::StartVerify(mut verifier, config) => {
                self.state = State::Verifying(Box::pin(async move {
                    let output = verifier.verify(&config).await.map_err(|_| todo!())?;

                    Ok((verifier, output))
                }));

                return self.poll(cx_std, cx, io);
            }
            State::Verifying(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    let (verifier, output) = res.unwrap();

                    self.state = State::FinishVerify(verifier, output);
                    if self.wants_state_update {
                        self.wants_state_update = false;
                        cx.waker.set_call();
                    }
                    println!("verifier finish verify");
                } else {
                    self.state = State::Verifying(fut);
                }
            }
            State::FinishVerify(verifier, output) => {
                self.state = State::FinishVerify(verifier, output);
            }
            State::Close(verifier) => {
                let fut = Box::pin(async move { verifier.close().await.map_err(|_| todo!()) });

                self.state = State::Closing(fut);

                println!("verifier start close");

                return self.poll(cx_std, cx, io);
            }
            State::Closing(mut fut) => {
                if let Poll::Ready(res) = fut.poll_unpin(cx_std) {
                    res?;

                    println!("verifier closed");

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
    Init(Verifier<state::Initialized>),
    Preprocess(Verifier<state::Initialized>),
    Preprocessing(Pin<Box<dyn Future<Output = Result<Verifier<state::Setup>, Error>>>>),
    Setup(Verifier<state::Setup>),
    StartCommit(Verifier<state::Setup>),
    Online(Pin<Box<dyn Future<Output = Result<Verifier<state::Committed>, Error>>>>),
    FinishCommit(Verifier<state::Committed>),
    Committed(Verifier<state::Committed>),
    StartVerify(Verifier<state::Committed>, VerifyConfig),
    Verifying(
        Pin<Box<dyn Future<Output = Result<(Verifier<state::Committed>, VerifierOutput), Error>>>>,
    ),
    FinishVerify(Verifier<state::Committed>, VerifierOutput),
    Close(Verifier<state::Committed>),
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
