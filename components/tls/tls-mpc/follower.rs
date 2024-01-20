pub(crate) mod follower {
    use std::{collections::VecDeque, future::Future, mem};
    use futures::{
        stream::{SplitSink, SplitStream},
        FutureExt, StreamExt,
    };
    use hmac_sha256 as prf;
    use key_exchange as ke;
    use ludi::{Address, FuturesAddress};
    use mpz_core::hash::Hash;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use prf::SessionKeys;
    use aead::Aead;
    use hmac_sha256::Prf;
    use ke::KeyExchange;
    use tls_core::{
        key::PublicKey,
        msgs::{
            alert::AlertMessagePayload, base::Payload, codec::Codec,
            enums::{AlertDescription, ContentType, NamedGroup, ProtocolVersion},
            message::{OpaqueMessage, PlainMessage},
        },
    };
    use crate::{
        error::Kind, msg::{CloseConnection, Commit, MpcTlsFollowerMsg, MpcTlsMessage},
        record_layer::{Decrypter, Encrypter},
        MpcTlsChannel, MpcTlsError, MpcTlsFollowerConfig,
    };
    /// Controller for MPC-TLS follower.
    pub type FollowerCtrl = MpcTlsFollowerCtrl<FuturesAddress<MpcTlsFollowerMsg>>;
    /// MPC-TLS follower.
    pub struct MpcTlsFollower {
        state: State,
        config: MpcTlsFollowerConfig,
        _sink: SplitSink<MpcTlsChannel, MpcTlsMessage>,
        stream: Option<SplitStream<MpcTlsChannel>>,
        ke: Box<dyn KeyExchange + Send>,
        prf: Box<dyn Prf + Send>,
        encrypter: Encrypter,
        decrypter: Decrypter,
        /// Whether the server has sent a CloseNotify alert
        close_notify: bool,
        /// Whether the leader has committed to the transcript
        committed: bool,
    }
    ///[`MpcTlsFollower`] controller.
    pub struct MpcTlsFollowerCtrl<A> {
        addr: A,
    }
    #[automatically_derived]
    impl<A: ::core::fmt::Debug> ::core::fmt::Debug for MpcTlsFollowerCtrl<A> {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "MpcTlsFollowerCtrl",
                "addr",
                &&self.addr,
            )
        }
    }
    #[automatically_derived]
    impl<A: ::core::clone::Clone> ::core::clone::Clone for MpcTlsFollowerCtrl<A> {
        #[inline]
        fn clone(&self) -> MpcTlsFollowerCtrl<A> {
            MpcTlsFollowerCtrl {
                addr: ::core::clone::Clone::clone(&self.addr),
            }
        }
    }
    impl MpcTlsFollower {
        ///Create a new [`MpcTlsFollower`] controller.
        pub fn controller<A>(addr: A) -> MpcTlsFollowerCtrl<A>
        where
            A: ::ludi::Address,
            <A as ::ludi::Address>::Message: ::ludi::Dispatch<Self>,
        {
            MpcTlsFollowerCtrl::from(addr)
        }
    }
    impl<A> From<A> for MpcTlsFollowerCtrl<A> {
        fn from(addr: A) -> Self {
            Self { addr }
        }
    }
    impl<A> ::ludi::Controller for MpcTlsFollowerCtrl<A>
    where
        A: ::ludi::Address,
        <A as ::ludi::Address>::Message: ::ludi::Dispatch<MpcTlsFollower>,
    {
        type Actor = MpcTlsFollower;
        type Address = A;
        type Message = <A as ::ludi::Address>::Message;
        fn address(&self) -> &Self::Address {
            &self.addr
        }
    }
    /// Data collected by the MPC-TLS follower.
    pub struct MpcTlsFollowerData {
        /// The prover's commitment to the handshake data
        pub handshake_commitment: Option<Hash>,
        /// The server's public key
        pub server_key: PublicKey,
        /// The total number of bytes sent
        pub bytes_sent: usize,
        /// The total number of bytes received
        pub bytes_recv: usize,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for MpcTlsFollowerData {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field4_finish(
                f,
                "MpcTlsFollowerData",
                "handshake_commitment",
                &self.handshake_commitment,
                "server_key",
                &self.server_key,
                "bytes_sent",
                &self.bytes_sent,
                "bytes_recv",
                &&self.bytes_recv,
            )
        }
    }
    impl ludi::Actor for MpcTlsFollower {
        type Stop = MpcTlsFollowerData;
        type Error = MpcTlsError;
        async fn stopped(&mut self) -> Result<Self::Stop, Self::Error> {
            {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "event tls-mpc/src/follower.rs:79",
                            "tls_mpc::follower",
                            ::tracing::Level::DEBUG,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(79u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &["message"],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::EVENT,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let enabled = ::tracing::Level::DEBUG
                    <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && ::tracing::Level::DEBUG
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        let interest = __CALLSITE.interest();
                        !interest.is_never()
                            && ::tracing::__macro_support::__is_enabled(
                                __CALLSITE.metadata(),
                                interest,
                            )
                    };
                if enabled {
                    (|value_set: ::tracing::field::ValueSet| {
                        let meta = __CALLSITE.metadata();
                        ::tracing::Event::dispatch(meta, &value_set);
                    })({
                        #[allow(unused_imports)]
                        use ::tracing::field::{debug, display, Value};
                        let mut iter = __CALLSITE.metadata().fields().iter();
                        __CALLSITE
                            .metadata()
                            .fields()
                            .value_set(
                                &[
                                    (
                                        &::core::iter::Iterator::next(&mut iter)
                                            .expect("FieldSet corrupted (this is a bug)"),
                                        ::core::option::Option::Some(
                                            &format_args!("follower actor stopped") as &dyn Value,
                                        ),
                                    ),
                                ],
                            )
                    });
                } else {
                }
            };
            let Closed { handshake_commitment, server_key } = self
                .state
                .take()
                .try_into_closed()?;
            let bytes_sent = self.encrypter.sent_bytes();
            let bytes_recv = self.decrypter.recv_bytes();
            Ok(MpcTlsFollowerData {
                handshake_commitment,
                server_key,
                bytes_sent,
                bytes_recv,
            })
        }
    }
    impl MpcTlsFollower {
        /// Create a new follower instance
        pub fn new(
            config: MpcTlsFollowerConfig,
            channel: MpcTlsChannel,
            ke: Box<dyn KeyExchange + Send>,
            prf: Box<dyn Prf + Send>,
            encrypter: Box<dyn Aead + Send>,
            decrypter: Box<dyn Aead + Send>,
        ) -> Self {
            let encrypter = Encrypter::new(
                encrypter,
                config.common().tx_transcript_id().to_string(),
                config.common().opaque_tx_transcript_id().to_string(),
            );
            let decrypter = Decrypter::new(
                decrypter,
                config.common().rx_transcript_id().to_string(),
                config.common().opaque_rx_transcript_id().to_string(),
            );
            let (_sink, stream) = channel.split();
            Self {
                state: State::Init,
                config,
                _sink,
                stream: Some(stream),
                ke,
                prf,
                encrypter,
                decrypter,
                close_notify: false,
                committed: false,
            }
        }
        /// Performs any one-time setup operations.
        pub async fn setup(&mut self) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "setup",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(138u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        let pms = self.ke.setup().await?;
                        self.prf.setup(pms.into_value()).await?;
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:138",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(138u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        /// Runs the follower actor.
        ///
        /// Returns a control handle and a future that resolves when the actor is stopped.
        ///
        /// # Note
        ///
        /// The future must be polled continuously to make progress.
        pub fn run(
            mut self,
        ) -> (
            FollowerCtrl,
            impl Future<Output = Result<MpcTlsFollowerData, MpcTlsError>>,
        ) {
            let (mut mailbox, addr) = ludi::mailbox::<MpcTlsFollowerMsg>(100);
            let ctrl = FollowerCtrl::from(addr.clone());
            let mut stream = self
                .stream
                .take()
                .expect("stream should be present from constructor");
            let mut remote_fut = Box::pin(async move {
                    while let Some(msg) = stream.next().await {
                        let msg = MpcTlsFollowerMsg::try_from(msg?)?;
                        addr.send_await(msg).await?;
                    }
                    Ok::<_, MpcTlsError>(())
                })
                .fuse();
            let mut actor_fut = Box::pin(async move {
                    ludi::run(&mut self, &mut mailbox).await
                })
                .fuse();
            let fut = async move {
                loop {
                    {
                        use ::futures_util::__private as __futures_crate;
                        {
                            enum __PrivResult<_0, _1> {
                                _0(_0),
                                _1(_1),
                            }
                            let __select_result = {
                                let mut _0 = &mut remote_fut;
                                let mut _1 = &mut actor_fut;
                                let mut __poll_fn = |
                                    __cx: &mut __futures_crate::task::Context<'_>|
                                {
                                    let mut __any_polled = false;
                                    let mut _0 = |
                                        __cx: &mut __futures_crate::task::Context<'_>|
                                    {
                                        let mut _0 = unsafe {
                                            __futures_crate::Pin::new_unchecked(&mut _0)
                                        };
                                        if __futures_crate::future::FusedFuture::is_terminated(
                                            &_0,
                                        ) {
                                            __futures_crate::None
                                        } else {
                                            __futures_crate::Some(
                                                __futures_crate::future::FutureExt::poll_unpin(
                                                        &mut _0,
                                                        __cx,
                                                    )
                                                    .map(__PrivResult::_0),
                                            )
                                        }
                                    };
                                    let _0: &mut dyn FnMut(
                                        &mut __futures_crate::task::Context<'_>,
                                    ) -> __futures_crate::Option<
                                            __futures_crate::task::Poll<_>,
                                        > = &mut _0;
                                    let mut _1 = |
                                        __cx: &mut __futures_crate::task::Context<'_>|
                                    {
                                        let mut _1 = unsafe {
                                            __futures_crate::Pin::new_unchecked(&mut _1)
                                        };
                                        if __futures_crate::future::FusedFuture::is_terminated(
                                            &_1,
                                        ) {
                                            __futures_crate::None
                                        } else {
                                            __futures_crate::Some(
                                                __futures_crate::future::FutureExt::poll_unpin(
                                                        &mut _1,
                                                        __cx,
                                                    )
                                                    .map(__PrivResult::_1),
                                            )
                                        }
                                    };
                                    let _1: &mut dyn FnMut(
                                        &mut __futures_crate::task::Context<'_>,
                                    ) -> __futures_crate::Option<
                                            __futures_crate::task::Poll<_>,
                                        > = &mut _1;
                                    let mut __select_arr = [_0, _1];
                                    __futures_crate::async_await::shuffle(&mut __select_arr);
                                    for poller in &mut __select_arr {
                                        let poller: &mut &mut dyn FnMut(
                                            &mut __futures_crate::task::Context<'_>,
                                        ) -> __futures_crate::Option<
                                                __futures_crate::task::Poll<_>,
                                            > = poller;
                                        match poller(__cx) {
                                            __futures_crate::Some(
                                                x @ __futures_crate::task::Poll::Ready(_),
                                            ) => return x,
                                            __futures_crate::Some(
                                                __futures_crate::task::Poll::Pending,
                                            ) => {
                                                __any_polled = true;
                                            }
                                            __futures_crate::None => {}
                                        }
                                    }
                                    if !__any_polled {
                                        {
                                            ::std::rt::begin_panic(
                                                "all futures in select! were completed,\
                    but no `complete =>` handler was provided",
                                            );
                                        }
                                    } else {
                                        __futures_crate::task::Poll::Pending
                                    }
                                };
                                __futures_crate::future::poll_fn(__poll_fn).await
                            };
                            match __select_result {
                                __PrivResult::_0(res) => {
                                    if let Err(e) = res {
                                        return Err(e);
                                    }
                                }
                                __PrivResult::_1(res) => return res,
                            }
                        }
                    }
                }
            };
            (ctrl, fut)
        }
        /// Returns the total number of bytes sent and received.
        fn total_bytes_transferred(&self) -> usize {
            self.encrypter.sent_bytes() + self.decrypter.recv_bytes()
        }
        fn check_transcript_length(&self, len: usize) -> Result<(), MpcTlsError> {
            let new_len = self.total_bytes_transferred() + len;
            if new_len > self.config.common().max_transcript_size() {
                return Err(
                    MpcTlsError::new(
                        Kind::Config,
                        {
                            let res = ::alloc::fmt::format(
                                format_args!(
                                    "max transcript size exceeded: {0} > {1}",
                                    new_len,
                                    self.config.common().max_transcript_size(),
                                ),
                            );
                            res
                        },
                    ),
                );
            }
            Ok(())
        }
        fn accepting_messages(&self) -> Result<(), MpcTlsError> {
            if self.close_notify {
                return Err(
                    MpcTlsError::new(
                        Kind::PeerMisbehaved,
                        "attempted to commit a message after receiving CloseNotify",
                    ),
                );
            }
            if self.committed {
                return Err(
                    MpcTlsError::new(
                        Kind::PeerMisbehaved,
                        "attempted to commit a new message after committing transcript",
                    ),
                );
            }
            Ok(())
        }
        async fn compute_client_key(&mut self) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "compute_client_key",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(238u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        self.state.take().try_into_init()?;
                        _ = self
                            .ke
                            .compute_client_key(
                                p256::SecretKey::random(&mut rand::rngs::OsRng),
                            )
                            .await?;
                        self.state = State::ClientKey;
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:238",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(238u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn compute_key_exchange(
            &mut self,
            handshake_commitment: Option<Hash>,
        ) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "compute_key_exchange",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(255u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        self.state.take().try_into_client_key()?;
                        if self.config.common().handshake_commit()
                            && handshake_commitment.is_none()
                        {
                            return Err(
                                MpcTlsError::new(
                                    Kind::PeerMisbehaved,
                                    "handshake commitment missing",
                                ),
                            );
                        }
                        self.ke.compute_pms().await?;
                        let server_key = self
                            .ke
                            .server_key()
                            .expect("server key should be set after computing pms");
                        let SessionKeys {
                            client_write_key,
                            server_write_key,
                            client_iv,
                            server_iv,
                        } = self.prf.compute_session_keys_blind().await?;
                        self.encrypter.set_key(client_write_key, client_iv).await?;
                        self.decrypter.set_key(server_write_key, server_iv).await?;
                        self
                            .state = State::Ke(Ke {
                            handshake_commitment,
                            server_key: PublicKey::new(
                                NamedGroup::secp256r1,
                                server_key.to_encoded_point(false).as_bytes(),
                            ),
                        });
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:255",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(255u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn client_finished_vd(&mut self) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "client_finished_vd",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(302u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        let Ke { handshake_commitment, server_key } = self
                            .state
                            .take()
                            .try_into_ke()?;
                        self.prf.compute_client_finished_vd_blind().await?;
                        self
                            .state = State::Cf(Cf {
                            handshake_commitment,
                            server_key,
                        });
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:302",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(302u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn server_finished_vd(&mut self) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "server_finished_vd",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(322u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        let Sf { handshake_commitment, server_key } = self
                            .state
                            .take()
                            .try_into_sf()?;
                        self.prf.compute_server_finished_vd_blind().await?;
                        self
                            .state = State::Active(Active {
                            handshake_commitment,
                            server_key,
                            buffer: Default::default(),
                        });
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:322",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(322u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn encrypt_client_finished(&mut self) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "encrypt_client_finished",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(343u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        let Cf { handshake_commitment, server_key } = self
                            .state
                            .take()
                            .try_into_cf()?;
                        self.encrypter
                            .encrypt_blind(
                                ContentType::Handshake,
                                ProtocolVersion::TLSv1_2,
                                16,
                            )
                            .await?;
                        self
                            .state = State::Sf(Sf {
                            handshake_commitment,
                            server_key,
                        });
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:343",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(343u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn encrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "encrypt_alert",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(365u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        self.accepting_messages()?;
                        if let Some(alert) = AlertMessagePayload::read_bytes(&msg) {
                            if alert.description != AlertDescription::CloseNotify {
                                return Err(
                                    MpcTlsError::new(
                                        Kind::PeerMisbehaved,
                                        "attempted to send an alert other than CloseNotify",
                                    ),
                                );
                            }
                        } else {
                            return Err(
                                MpcTlsError::new(
                                    Kind::PeerMisbehaved,
                                    "invalid alert message",
                                ),
                            );
                        }
                        self.encrypter
                            .encrypt_public(PlainMessage {
                                typ: ContentType::Alert,
                                version: ProtocolVersion::TLSv1_2,
                                payload: Payload::new(msg),
                            })
                            .await?;
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:365",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(365u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn encrypt_message(&mut self, len: usize) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "encrypt_message",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(397u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        self.accepting_messages()?;
                        self.check_transcript_length(len)?;
                        self.state.try_as_active()?;
                        self.encrypter
                            .encrypt_blind(
                                ContentType::ApplicationData,
                                ProtocolVersion::TLSv1_2,
                                len,
                            )
                            .await?;
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:397",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(397u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        fn commit_message(&mut self, payload: Vec<u8>) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span;
            let __tracing_attr_guard;
            if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                && tracing::Level::TRACE
                    <= ::tracing::level_filters::LevelFilter::current() || { false }
            {
                __tracing_attr_span = {
                    use ::tracing::__macro_support::Callsite as _;
                    static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                        static META: ::tracing::Metadata<'static> = {
                            ::tracing_core::metadata::Metadata::new(
                                "commit_message",
                                "tls_mpc::follower",
                                tracing::Level::TRACE,
                                ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                ::core::option::Option::Some(413u32),
                                ::core::option::Option::Some("tls_mpc::follower"),
                                ::tracing_core::field::FieldSet::new(
                                    &[],
                                    ::tracing_core::callsite::Identifier(&__CALLSITE),
                                ),
                                ::tracing::metadata::Kind::SPAN,
                            )
                        };
                        ::tracing::callsite::DefaultCallsite::new(&META)
                    };
                    let mut interest = ::tracing::subscriber::Interest::never();
                    if tracing::Level::TRACE
                        <= ::tracing::level_filters::STATIC_MAX_LEVEL
                        && tracing::Level::TRACE
                            <= ::tracing::level_filters::LevelFilter::current()
                        && {
                            interest = __CALLSITE.interest();
                            !interest.is_never()
                        }
                        && ::tracing::__macro_support::__is_enabled(
                            __CALLSITE.metadata(),
                            interest,
                        )
                    {
                        let meta = __CALLSITE.metadata();
                        ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                    } else {
                        let span = ::tracing::__macro_support::__disabled_span(
                            __CALLSITE.metadata(),
                        );
                        {};
                        span
                    }
                };
                __tracing_attr_guard = __tracing_attr_span.enter();
            }
            #[allow(clippy::redundant_closure_call)]
            match (move || {
                #[allow(
                    unknown_lints,
                    unreachable_code,
                    clippy::diverging_sub_expression,
                    clippy::let_unit_value,
                    clippy::unreachable,
                    clippy::let_with_type_underscore,
                    clippy::empty_loop
                )]
                if false {
                    let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                    return __tracing_attr_fake_return;
                }
                {
                    self.accepting_messages()?;
                    self.check_transcript_length(payload.len())?;
                    let Active { buffer, .. } = self.state.try_as_active_mut()?;
                    buffer
                        .push_back(OpaqueMessage {
                            typ: ContentType::ApplicationData,
                            version: ProtocolVersion::TLSv1_2,
                            payload: Payload::new(payload),
                        });
                    Ok(())
                }
            })() {
                #[allow(clippy::unit_arg)]
                Ok(x) => Ok(x),
                Err(e) => {
                    {
                        use ::tracing::__macro_support::Callsite as _;
                        static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                            static META: ::tracing::Metadata<'static> = {
                                ::tracing_core::metadata::Metadata::new(
                                    "event tls-mpc/src/follower.rs:413",
                                    "tls_mpc::follower",
                                    tracing::Level::ERROR,
                                    ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                    ::core::option::Option::Some(413u32),
                                    ::core::option::Option::Some("tls_mpc::follower"),
                                    ::tracing_core::field::FieldSet::new(
                                        &["error"],
                                        ::tracing_core::callsite::Identifier(&__CALLSITE),
                                    ),
                                    ::tracing::metadata::Kind::EVENT,
                                )
                            };
                            ::tracing::callsite::DefaultCallsite::new(&META)
                        };
                        let enabled = tracing::Level::ERROR
                            <= ::tracing::level_filters::STATIC_MAX_LEVEL
                            && tracing::Level::ERROR
                                <= ::tracing::level_filters::LevelFilter::current()
                            && {
                                let interest = __CALLSITE.interest();
                                !interest.is_never()
                                    && ::tracing::__macro_support::__is_enabled(
                                        __CALLSITE.metadata(),
                                        interest,
                                    )
                            };
                        if enabled {
                            (|value_set: ::tracing::field::ValueSet| {
                                let meta = __CALLSITE.metadata();
                                ::tracing::Event::dispatch(meta, &value_set);
                            })({
                                #[allow(unused_imports)]
                                use ::tracing::field::{debug, display, Value};
                                let mut iter = __CALLSITE.metadata().fields().iter();
                                __CALLSITE
                                    .metadata()
                                    .fields()
                                    .value_set(
                                        &[
                                            (
                                                &::core::iter::Iterator::next(&mut iter)
                                                    .expect("FieldSet corrupted (this is a bug)"),
                                                ::core::option::Option::Some(&display(&e) as &dyn Value),
                                            ),
                                        ],
                                    )
                            });
                        } else {
                        }
                    };
                    Err(e)
                }
            }
        }
        async fn decrypt_server_finished(
            &mut self,
            msg: Vec<u8>,
        ) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "decrypt_server_finished",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(431u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        self.state.try_as_sf()?;
                        self.decrypter
                            .decrypt_blind(OpaqueMessage {
                                typ: ContentType::Handshake,
                                version: ProtocolVersion::TLSv1_2,
                                payload: Payload::new(msg),
                            })
                            .await?;
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:431",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(431u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn decrypt_alert(&mut self, msg: Vec<u8>) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "decrypt_alert",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(449u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        self.accepting_messages()?;
                        self.state.try_as_active()?;
                        let alert = self
                            .decrypter
                            .decrypt_public(OpaqueMessage {
                                typ: ContentType::Alert,
                                version: ProtocolVersion::TLSv1_2,
                                payload: Payload::new(msg),
                            })
                            .await?;
                        let Some(alert) = AlertMessagePayload::read_bytes(
                            &alert.payload.0,
                        ) else {
                            return Err(
                                MpcTlsError::other("server sent an invalid alert"),
                            );
                        };
                        if alert.description != AlertDescription::CloseNotify {
                            return Err(
                                MpcTlsError::new(
                                    Kind::PeerMisbehaved,
                                    "server sent a fatal alert",
                                ),
                            );
                        }
                        self.close_notify = true;
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:449",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(449u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        async fn decrypt_message(&mut self) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span = {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "decrypt_message",
                            "tls_mpc::follower",
                            tracing::Level::TRACE,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(482u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &[],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::SPAN,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let mut interest = ::tracing::subscriber::Interest::never();
                if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && tracing::Level::TRACE
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        interest = __CALLSITE.interest();
                        !interest.is_never()
                    }
                    && ::tracing::__macro_support::__is_enabled(
                        __CALLSITE.metadata(),
                        interest,
                    )
                {
                    let meta = __CALLSITE.metadata();
                    ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                } else {
                    let span = ::tracing::__macro_support::__disabled_span(
                        __CALLSITE.metadata(),
                    );
                    {};
                    span
                }
            };
            let __tracing_instrument_future = async move {
                match async move {
                    #[allow(
                        unknown_lints,
                        unreachable_code,
                        clippy::diverging_sub_expression,
                        clippy::let_unit_value,
                        clippy::unreachable,
                        clippy::let_with_type_underscore,
                        clippy::empty_loop
                    )]
                    if false {
                        let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                        return __tracing_attr_fake_return;
                    }
                    {
                        let Active { buffer, .. } = self.state.try_as_active_mut()?;
                        let msg = buffer
                            .pop_front()
                            .ok_or(
                                MpcTlsError::new(
                                    Kind::PeerMisbehaved,
                                    "attempted to decrypt message when no messages are committed",
                                ),
                            )?;
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:493",
                                        "tls_mpc::follower",
                                        ::tracing::Level::DEBUG,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(493u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["message"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = ::tracing::Level::DEBUG
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && ::tracing::Level::DEBUG
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(
                                                        &format_args!("decrypting message") as &dyn Value,
                                                    ),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        if self.committed {
                            self.decrypter.verify_plaintext(msg).await?;
                        } else {
                            self.decrypter.decrypt_blind(msg).await?;
                        }
                        Ok(())
                    }
                }
                    .await
                {
                    #[allow(clippy::unit_arg)]
                    Ok(x) => Ok(x),
                    Err(e) => {
                        {
                            use ::tracing::__macro_support::Callsite as _;
                            static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                                static META: ::tracing::Metadata<'static> = {
                                    ::tracing_core::metadata::Metadata::new(
                                        "event tls-mpc/src/follower.rs:482",
                                        "tls_mpc::follower",
                                        tracing::Level::ERROR,
                                        ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                        ::core::option::Option::Some(482u32),
                                        ::core::option::Option::Some("tls_mpc::follower"),
                                        ::tracing_core::field::FieldSet::new(
                                            &["error"],
                                            ::tracing_core::callsite::Identifier(&__CALLSITE),
                                        ),
                                        ::tracing::metadata::Kind::EVENT,
                                    )
                                };
                                ::tracing::callsite::DefaultCallsite::new(&META)
                            };
                            let enabled = tracing::Level::ERROR
                                <= ::tracing::level_filters::STATIC_MAX_LEVEL
                                && tracing::Level::ERROR
                                    <= ::tracing::level_filters::LevelFilter::current()
                                && {
                                    let interest = __CALLSITE.interest();
                                    !interest.is_never()
                                        && ::tracing::__macro_support::__is_enabled(
                                            __CALLSITE.metadata(),
                                            interest,
                                        )
                                };
                            if enabled {
                                (|value_set: ::tracing::field::ValueSet| {
                                    let meta = __CALLSITE.metadata();
                                    ::tracing::Event::dispatch(meta, &value_set);
                                })({
                                    #[allow(unused_imports)]
                                    use ::tracing::field::{debug, display, Value};
                                    let mut iter = __CALLSITE.metadata().fields().iter();
                                    __CALLSITE
                                        .metadata()
                                        .fields()
                                        .value_set(
                                            &[
                                                (
                                                    &::core::iter::Iterator::next(&mut iter)
                                                        .expect("FieldSet corrupted (this is a bug)"),
                                                    ::core::option::Option::Some(&display(&e) as &dyn Value),
                                                ),
                                            ],
                                        )
                                });
                            } else {
                            }
                        };
                        Err(e)
                    }
                }
            };
            if !__tracing_attr_span.is_disabled() {
                tracing::Instrument::instrument(
                        __tracing_instrument_future,
                        __tracing_attr_span,
                    )
                    .await
            } else {
                __tracing_instrument_future.await
            }
        }
        fn close_connection(&mut self) -> Result<(), MpcTlsError> {
            {}
            let __tracing_attr_span;
            let __tracing_attr_guard;
            if tracing::Level::TRACE <= ::tracing::level_filters::STATIC_MAX_LEVEL
                && tracing::Level::TRACE
                    <= ::tracing::level_filters::LevelFilter::current() || { false }
            {
                __tracing_attr_span = {
                    use ::tracing::__macro_support::Callsite as _;
                    static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                        static META: ::tracing::Metadata<'static> = {
                            ::tracing_core::metadata::Metadata::new(
                                "close_connection",
                                "tls_mpc::follower",
                                tracing::Level::TRACE,
                                ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                ::core::option::Option::Some(506u32),
                                ::core::option::Option::Some("tls_mpc::follower"),
                                ::tracing_core::field::FieldSet::new(
                                    &[],
                                    ::tracing_core::callsite::Identifier(&__CALLSITE),
                                ),
                                ::tracing::metadata::Kind::SPAN,
                            )
                        };
                        ::tracing::callsite::DefaultCallsite::new(&META)
                    };
                    let mut interest = ::tracing::subscriber::Interest::never();
                    if tracing::Level::TRACE
                        <= ::tracing::level_filters::STATIC_MAX_LEVEL
                        && tracing::Level::TRACE
                            <= ::tracing::level_filters::LevelFilter::current()
                        && {
                            interest = __CALLSITE.interest();
                            !interest.is_never()
                        }
                        && ::tracing::__macro_support::__is_enabled(
                            __CALLSITE.metadata(),
                            interest,
                        )
                    {
                        let meta = __CALLSITE.metadata();
                        ::tracing::Span::new(meta, &{ meta.fields().value_set(&[]) })
                    } else {
                        let span = ::tracing::__macro_support::__disabled_span(
                            __CALLSITE.metadata(),
                        );
                        {};
                        span
                    }
                };
                __tracing_attr_guard = __tracing_attr_span.enter();
            }
            #[allow(clippy::redundant_closure_call)]
            match (move || {
                #[allow(
                    unknown_lints,
                    unreachable_code,
                    clippy::diverging_sub_expression,
                    clippy::let_unit_value,
                    clippy::unreachable,
                    clippy::let_with_type_underscore,
                    clippy::empty_loop
                )]
                if false {
                    let __tracing_attr_fake_return: Result<(), MpcTlsError> = loop {};
                    return __tracing_attr_fake_return;
                }
                {
                    let Active { handshake_commitment, server_key, buffer } = self
                        .state
                        .take()
                        .try_into_active()?;
                    if !buffer.is_empty() {
                        return Err(
                            MpcTlsError::new(
                                Kind::PeerMisbehaved,
                                "attempted to close connection without proving all messages",
                            ),
                        );
                    }
                    self
                        .state = State::Closed(Closed {
                        handshake_commitment,
                        server_key,
                    });
                    Ok(())
                }
            })() {
                #[allow(clippy::unit_arg)]
                Ok(x) => Ok(x),
                Err(e) => {
                    {
                        use ::tracing::__macro_support::Callsite as _;
                        static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                            static META: ::tracing::Metadata<'static> = {
                                ::tracing_core::metadata::Metadata::new(
                                    "event tls-mpc/src/follower.rs:506",
                                    "tls_mpc::follower",
                                    tracing::Level::ERROR,
                                    ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                                    ::core::option::Option::Some(506u32),
                                    ::core::option::Option::Some("tls_mpc::follower"),
                                    ::tracing_core::field::FieldSet::new(
                                        &["error"],
                                        ::tracing_core::callsite::Identifier(&__CALLSITE),
                                    ),
                                    ::tracing::metadata::Kind::EVENT,
                                )
                            };
                            ::tracing::callsite::DefaultCallsite::new(&META)
                        };
                        let enabled = tracing::Level::ERROR
                            <= ::tracing::level_filters::STATIC_MAX_LEVEL
                            && tracing::Level::ERROR
                                <= ::tracing::level_filters::LevelFilter::current()
                            && {
                                let interest = __CALLSITE.interest();
                                !interest.is_never()
                                    && ::tracing::__macro_support::__is_enabled(
                                        __CALLSITE.metadata(),
                                        interest,
                                    )
                            };
                        if enabled {
                            (|value_set: ::tracing::field::ValueSet| {
                                let meta = __CALLSITE.metadata();
                                ::tracing::Event::dispatch(meta, &value_set);
                            })({
                                #[allow(unused_imports)]
                                use ::tracing::field::{debug, display, Value};
                                let mut iter = __CALLSITE.metadata().fields().iter();
                                __CALLSITE
                                    .metadata()
                                    .fields()
                                    .value_set(
                                        &[
                                            (
                                                &::core::iter::Iterator::next(&mut iter)
                                                    .expect("FieldSet corrupted (this is a bug)"),
                                                ::core::option::Option::Some(&display(&e) as &dyn Value),
                                            ),
                                        ],
                                    )
                            });
                        } else {
                        }
                    };
                    Err(e)
                }
            }
        }
        async fn commit(&mut self) -> Result<(), MpcTlsError> {
            let Active { buffer, .. } = self.state.try_as_active()?;
            {
                use ::tracing::__macro_support::Callsite as _;
                static __CALLSITE: ::tracing::callsite::DefaultCallsite = {
                    static META: ::tracing::Metadata<'static> = {
                        ::tracing_core::metadata::Metadata::new(
                            "event tls-mpc/src/follower.rs:534",
                            "tls_mpc::follower",
                            ::tracing::Level::DEBUG,
                            ::core::option::Option::Some("tls-mpc/src/follower.rs"),
                            ::core::option::Option::Some(534u32),
                            ::core::option::Option::Some("tls_mpc::follower"),
                            ::tracing_core::field::FieldSet::new(
                                &["message"],
                                ::tracing_core::callsite::Identifier(&__CALLSITE),
                            ),
                            ::tracing::metadata::Kind::EVENT,
                        )
                    };
                    ::tracing::callsite::DefaultCallsite::new(&META)
                };
                let enabled = ::tracing::Level::DEBUG
                    <= ::tracing::level_filters::STATIC_MAX_LEVEL
                    && ::tracing::Level::DEBUG
                        <= ::tracing::level_filters::LevelFilter::current()
                    && {
                        let interest = __CALLSITE.interest();
                        !interest.is_never()
                            && ::tracing::__macro_support::__is_enabled(
                                __CALLSITE.metadata(),
                                interest,
                            )
                    };
                if enabled {
                    (|value_set: ::tracing::field::ValueSet| {
                        let meta = __CALLSITE.metadata();
                        ::tracing::Event::dispatch(meta, &value_set);
                    })({
                        #[allow(unused_imports)]
                        use ::tracing::field::{debug, display, Value};
                        let mut iter = __CALLSITE.metadata().fields().iter();
                        __CALLSITE
                            .metadata()
                            .fields()
                            .value_set(
                                &[
                                    (
                                        &::core::iter::Iterator::next(&mut iter)
                                            .expect("FieldSet corrupted (this is a bug)"),
                                        ::core::option::Option::Some(
                                            &format_args!("leader committed transcript") as &dyn Value,
                                        ),
                                    ),
                                ],
                            )
                    });
                } else {
                }
            };
            if !buffer.is_empty() {
                self.decrypter.decode_key_blind().await?;
            }
            Ok(())
        }
    }
    pub struct ComputeClientKey;
    #[automatically_derived]
    impl ::core::fmt::Debug for ComputeClientKey {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "ComputeClientKey")
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ComputeClientKey {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_unit_struct(
                    __serializer,
                    "ComputeClientKey",
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for ComputeClientKey {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<ComputeClientKey>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = ComputeClientKey;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "unit struct ComputeClientKey",
                        )
                    }
                    #[inline]
                    fn visit_unit<__E>(
                        self,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        _serde::__private::Ok(ComputeClientKey)
                    }
                }
                _serde::Deserializer::deserialize_unit_struct(
                    __deserializer,
                    "ComputeClientKey",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<ComputeClientKey>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for ComputeClientKey {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for ComputeClientKey
    where
        A: ::ludi::Actor + ::ludi::Handler<ComputeClientKey>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<ComputeClientKey>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct ComputeKeyExchange {
        pub handshake_commitment: Option<Hash>,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for ComputeKeyExchange {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "ComputeKeyExchange",
                "handshake_commitment",
                &&self.handshake_commitment,
            )
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ComputeKeyExchange {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "ComputeKeyExchange",
                    false as usize + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "handshake_commitment",
                    &self.handshake_commitment,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for ComputeKeyExchange {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                #[doc(hidden)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                #[doc(hidden)]
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "handshake_commitment" => {
                                _serde::__private::Ok(__Field::__field0)
                            }
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"handshake_commitment" => {
                                _serde::__private::Ok(__Field::__field0)
                            }
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<ComputeKeyExchange>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = ComputeKeyExchange;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct ComputeKeyExchange",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match _serde::de::SeqAccess::next_element::<
                            Option<Hash>,
                        >(&mut __seq)? {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct ComputeKeyExchange with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(ComputeKeyExchange {
                            handshake_commitment: __field0,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<Option<Hash>> = _serde::__private::None;
                        while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                            __Field,
                        >(&mut __map)? {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "handshake_commitment",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        _serde::de::MapAccess::next_value::<
                                            Option<Hash>,
                                        >(&mut __map)?,
                                    );
                                }
                                _ => {
                                    let _ = _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)?;
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                _serde::__private::de::missing_field(
                                    "handshake_commitment",
                                )?
                            }
                        };
                        _serde::__private::Ok(ComputeKeyExchange {
                            handshake_commitment: __field0,
                        })
                    }
                }
                #[doc(hidden)]
                const FIELDS: &'static [&'static str] = &["handshake_commitment"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "ComputeKeyExchange",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<ComputeKeyExchange>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for ComputeKeyExchange {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for ComputeKeyExchange
    where
        A: ::ludi::Actor + ::ludi::Handler<ComputeKeyExchange>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<ComputeKeyExchange>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct ClientFinishedVd;
    #[automatically_derived]
    impl ::core::fmt::Debug for ClientFinishedVd {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "ClientFinishedVd")
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ClientFinishedVd {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_unit_struct(
                    __serializer,
                    "ClientFinishedVd",
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for ClientFinishedVd {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<ClientFinishedVd>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = ClientFinishedVd;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "unit struct ClientFinishedVd",
                        )
                    }
                    #[inline]
                    fn visit_unit<__E>(
                        self,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        _serde::__private::Ok(ClientFinishedVd)
                    }
                }
                _serde::Deserializer::deserialize_unit_struct(
                    __deserializer,
                    "ClientFinishedVd",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<ClientFinishedVd>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for ClientFinishedVd {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for ClientFinishedVd
    where
        A: ::ludi::Actor + ::ludi::Handler<ClientFinishedVd>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<ClientFinishedVd>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct ServerFinishedVd;
    #[automatically_derived]
    impl ::core::fmt::Debug for ServerFinishedVd {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "ServerFinishedVd")
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for ServerFinishedVd {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_unit_struct(
                    __serializer,
                    "ServerFinishedVd",
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for ServerFinishedVd {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<ServerFinishedVd>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = ServerFinishedVd;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "unit struct ServerFinishedVd",
                        )
                    }
                    #[inline]
                    fn visit_unit<__E>(
                        self,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        _serde::__private::Ok(ServerFinishedVd)
                    }
                }
                _serde::Deserializer::deserialize_unit_struct(
                    __deserializer,
                    "ServerFinishedVd",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<ServerFinishedVd>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for ServerFinishedVd {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for ServerFinishedVd
    where
        A: ::ludi::Actor + ::ludi::Handler<ServerFinishedVd>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<ServerFinishedVd>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct EncryptClientFinished;
    #[automatically_derived]
    impl ::core::fmt::Debug for EncryptClientFinished {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "EncryptClientFinished")
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for EncryptClientFinished {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_unit_struct(
                    __serializer,
                    "EncryptClientFinished",
                )
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for EncryptClientFinished {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<EncryptClientFinished>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = EncryptClientFinished;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "unit struct EncryptClientFinished",
                        )
                    }
                    #[inline]
                    fn visit_unit<__E>(
                        self,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        _serde::__private::Ok(EncryptClientFinished)
                    }
                }
                _serde::Deserializer::deserialize_unit_struct(
                    __deserializer,
                    "EncryptClientFinished",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<EncryptClientFinished>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for EncryptClientFinished {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for EncryptClientFinished
    where
        A: ::ludi::Actor + ::ludi::Handler<EncryptClientFinished>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<EncryptClientFinished>::process(actor, self, ctx, ret)
                .await;
        }
    }
    pub struct EncryptAlert {
        pub msg: Vec<u8>,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for EncryptAlert {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "EncryptAlert",
                "msg",
                &&self.msg,
            )
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for EncryptAlert {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "EncryptAlert",
                    false as usize + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "msg",
                    &self.msg,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for EncryptAlert {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                #[doc(hidden)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                #[doc(hidden)]
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "msg" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"msg" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<EncryptAlert>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = EncryptAlert;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct EncryptAlert",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match _serde::de::SeqAccess::next_element::<
                            Vec<u8>,
                        >(&mut __seq)? {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct EncryptAlert with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(EncryptAlert { msg: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<Vec<u8>> = _serde::__private::None;
                        while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                            __Field,
                        >(&mut __map)? {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("msg"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        _serde::de::MapAccess::next_value::<Vec<u8>>(&mut __map)?,
                                    );
                                }
                                _ => {
                                    let _ = _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)?;
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                _serde::__private::de::missing_field("msg")?
                            }
                        };
                        _serde::__private::Ok(EncryptAlert { msg: __field0 })
                    }
                }
                #[doc(hidden)]
                const FIELDS: &'static [&'static str] = &["msg"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "EncryptAlert",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<EncryptAlert>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for EncryptAlert {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for EncryptAlert
    where
        A: ::ludi::Actor + ::ludi::Handler<EncryptAlert>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<EncryptAlert>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct EncryptMessage {
        pub len: usize,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for EncryptMessage {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "EncryptMessage",
                "len",
                &&self.len,
            )
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for EncryptMessage {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "EncryptMessage",
                    false as usize + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "len",
                    &self.len,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for EncryptMessage {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                #[doc(hidden)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                #[doc(hidden)]
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "len" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"len" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<EncryptMessage>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = EncryptMessage;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct EncryptMessage",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match _serde::de::SeqAccess::next_element::<
                            usize,
                        >(&mut __seq)? {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct EncryptMessage with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(EncryptMessage { len: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<usize> = _serde::__private::None;
                        while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                            __Field,
                        >(&mut __map)? {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("len"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        _serde::de::MapAccess::next_value::<usize>(&mut __map)?,
                                    );
                                }
                                _ => {
                                    let _ = _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)?;
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                _serde::__private::de::missing_field("len")?
                            }
                        };
                        _serde::__private::Ok(EncryptMessage { len: __field0 })
                    }
                }
                #[doc(hidden)]
                const FIELDS: &'static [&'static str] = &["len"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "EncryptMessage",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<EncryptMessage>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for EncryptMessage {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for EncryptMessage
    where
        A: ::ludi::Actor + ::ludi::Handler<EncryptMessage>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<EncryptMessage>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct DecryptServerFinished {
        pub ciphertext: Vec<u8>,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for DecryptServerFinished {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "DecryptServerFinished",
                "ciphertext",
                &&self.ciphertext,
            )
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for DecryptServerFinished {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "DecryptServerFinished",
                    false as usize + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "ciphertext",
                    &self.ciphertext,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for DecryptServerFinished {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                #[doc(hidden)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                #[doc(hidden)]
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "ciphertext" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"ciphertext" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<DecryptServerFinished>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = DecryptServerFinished;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct DecryptServerFinished",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match _serde::de::SeqAccess::next_element::<
                            Vec<u8>,
                        >(&mut __seq)? {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct DecryptServerFinished with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(DecryptServerFinished {
                            ciphertext: __field0,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<Vec<u8>> = _serde::__private::None;
                        while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                            __Field,
                        >(&mut __map)? {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "ciphertext",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        _serde::de::MapAccess::next_value::<Vec<u8>>(&mut __map)?,
                                    );
                                }
                                _ => {
                                    let _ = _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)?;
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                _serde::__private::de::missing_field("ciphertext")?
                            }
                        };
                        _serde::__private::Ok(DecryptServerFinished {
                            ciphertext: __field0,
                        })
                    }
                }
                #[doc(hidden)]
                const FIELDS: &'static [&'static str] = &["ciphertext"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "DecryptServerFinished",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<DecryptServerFinished>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for DecryptServerFinished {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for DecryptServerFinished
    where
        A: ::ludi::Actor + ::ludi::Handler<DecryptServerFinished>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<DecryptServerFinished>::process(actor, self, ctx, ret)
                .await;
        }
    }
    pub struct DecryptAlert {
        pub ciphertext: Vec<u8>,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for DecryptAlert {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "DecryptAlert",
                "ciphertext",
                &&self.ciphertext,
            )
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for DecryptAlert {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "DecryptAlert",
                    false as usize + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "ciphertext",
                    &self.ciphertext,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for DecryptAlert {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                #[doc(hidden)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                #[doc(hidden)]
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "ciphertext" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"ciphertext" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<DecryptAlert>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = DecryptAlert;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct DecryptAlert",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match _serde::de::SeqAccess::next_element::<
                            Vec<u8>,
                        >(&mut __seq)? {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct DecryptAlert with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(DecryptAlert {
                            ciphertext: __field0,
                        })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<Vec<u8>> = _serde::__private::None;
                        while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                            __Field,
                        >(&mut __map)? {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field(
                                                "ciphertext",
                                            ),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        _serde::de::MapAccess::next_value::<Vec<u8>>(&mut __map)?,
                                    );
                                }
                                _ => {
                                    let _ = _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)?;
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                _serde::__private::de::missing_field("ciphertext")?
                            }
                        };
                        _serde::__private::Ok(DecryptAlert {
                            ciphertext: __field0,
                        })
                    }
                }
                #[doc(hidden)]
                const FIELDS: &'static [&'static str] = &["ciphertext"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "DecryptAlert",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<DecryptAlert>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for DecryptAlert {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for DecryptAlert
    where
        A: ::ludi::Actor + ::ludi::Handler<DecryptAlert>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<DecryptAlert>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct CommitMessage {
        pub msg: Vec<u8>,
    }
    #[automatically_derived]
    impl ::core::fmt::Debug for CommitMessage {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::debug_struct_field1_finish(
                f,
                "CommitMessage",
                "msg",
                &&self.msg,
            )
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for CommitMessage {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                let mut __serde_state = _serde::Serializer::serialize_struct(
                    __serializer,
                    "CommitMessage",
                    false as usize + 1,
                )?;
                _serde::ser::SerializeStruct::serialize_field(
                    &mut __serde_state,
                    "msg",
                    &self.msg,
                )?;
                _serde::ser::SerializeStruct::end(__serde_state)
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for CommitMessage {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[allow(non_camel_case_types)]
                #[doc(hidden)]
                enum __Field {
                    __field0,
                    __ignore,
                }
                #[doc(hidden)]
                struct __FieldVisitor;
                impl<'de> _serde::de::Visitor<'de> for __FieldVisitor {
                    type Value = __Field;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "field identifier",
                        )
                    }
                    fn visit_u64<__E>(
                        self,
                        __value: u64,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            0u64 => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_str<__E>(
                        self,
                        __value: &str,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            "msg" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                    fn visit_bytes<__E>(
                        self,
                        __value: &[u8],
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        match __value {
                            b"msg" => _serde::__private::Ok(__Field::__field0),
                            _ => _serde::__private::Ok(__Field::__ignore),
                        }
                    }
                }
                impl<'de> _serde::Deserialize<'de> for __Field {
                    #[inline]
                    fn deserialize<__D>(
                        __deserializer: __D,
                    ) -> _serde::__private::Result<Self, __D::Error>
                    where
                        __D: _serde::Deserializer<'de>,
                    {
                        _serde::Deserializer::deserialize_identifier(
                            __deserializer,
                            __FieldVisitor,
                        )
                    }
                }
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<CommitMessage>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = CommitMessage;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "struct CommitMessage",
                        )
                    }
                    #[inline]
                    fn visit_seq<__A>(
                        self,
                        mut __seq: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::SeqAccess<'de>,
                    {
                        let __field0 = match _serde::de::SeqAccess::next_element::<
                            Vec<u8>,
                        >(&mut __seq)? {
                            _serde::__private::Some(__value) => __value,
                            _serde::__private::None => {
                                return _serde::__private::Err(
                                    _serde::de::Error::invalid_length(
                                        0usize,
                                        &"struct CommitMessage with 1 element",
                                    ),
                                );
                            }
                        };
                        _serde::__private::Ok(CommitMessage { msg: __field0 })
                    }
                    #[inline]
                    fn visit_map<__A>(
                        self,
                        mut __map: __A,
                    ) -> _serde::__private::Result<Self::Value, __A::Error>
                    where
                        __A: _serde::de::MapAccess<'de>,
                    {
                        let mut __field0: _serde::__private::Option<Vec<u8>> = _serde::__private::None;
                        while let _serde::__private::Some(__key) = _serde::de::MapAccess::next_key::<
                            __Field,
                        >(&mut __map)? {
                            match __key {
                                __Field::__field0 => {
                                    if _serde::__private::Option::is_some(&__field0) {
                                        return _serde::__private::Err(
                                            <__A::Error as _serde::de::Error>::duplicate_field("msg"),
                                        );
                                    }
                                    __field0 = _serde::__private::Some(
                                        _serde::de::MapAccess::next_value::<Vec<u8>>(&mut __map)?,
                                    );
                                }
                                _ => {
                                    let _ = _serde::de::MapAccess::next_value::<
                                        _serde::de::IgnoredAny,
                                    >(&mut __map)?;
                                }
                            }
                        }
                        let __field0 = match __field0 {
                            _serde::__private::Some(__field0) => __field0,
                            _serde::__private::None => {
                                _serde::__private::de::missing_field("msg")?
                            }
                        };
                        _serde::__private::Ok(CommitMessage { msg: __field0 })
                    }
                }
                #[doc(hidden)]
                const FIELDS: &'static [&'static str] = &["msg"];
                _serde::Deserializer::deserialize_struct(
                    __deserializer,
                    "CommitMessage",
                    FIELDS,
                    __Visitor {
                        marker: _serde::__private::PhantomData::<CommitMessage>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for CommitMessage {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for CommitMessage
    where
        A: ::ludi::Actor + ::ludi::Handler<CommitMessage>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<CommitMessage>::process(actor, self, ctx, ret).await;
        }
    }
    pub struct DecryptMessage;
    #[automatically_derived]
    impl ::core::fmt::Debug for DecryptMessage {
        #[inline]
        fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            ::core::fmt::Formatter::write_str(f, "DecryptMessage")
        }
    }
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl _serde::Serialize for DecryptMessage {
            fn serialize<__S>(
                &self,
                __serializer: __S,
            ) -> _serde::__private::Result<__S::Ok, __S::Error>
            where
                __S: _serde::Serializer,
            {
                _serde::Serializer::serialize_unit_struct(__serializer, "DecryptMessage")
            }
        }
    };
    #[doc(hidden)]
    #[allow(non_upper_case_globals, unused_attributes, unused_qualifications)]
    const _: () = {
        #[allow(unused_extern_crates, clippy::useless_attribute)]
        extern crate serde as _serde;
        #[automatically_derived]
        impl<'de> _serde::Deserialize<'de> for DecryptMessage {
            fn deserialize<__D>(
                __deserializer: __D,
            ) -> _serde::__private::Result<Self, __D::Error>
            where
                __D: _serde::Deserializer<'de>,
            {
                #[doc(hidden)]
                struct __Visitor<'de> {
                    marker: _serde::__private::PhantomData<DecryptMessage>,
                    lifetime: _serde::__private::PhantomData<&'de ()>,
                }
                impl<'de> _serde::de::Visitor<'de> for __Visitor<'de> {
                    type Value = DecryptMessage;
                    fn expecting(
                        &self,
                        __formatter: &mut _serde::__private::Formatter,
                    ) -> _serde::__private::fmt::Result {
                        _serde::__private::Formatter::write_str(
                            __formatter,
                            "unit struct DecryptMessage",
                        )
                    }
                    #[inline]
                    fn visit_unit<__E>(
                        self,
                    ) -> _serde::__private::Result<Self::Value, __E>
                    where
                        __E: _serde::de::Error,
                    {
                        _serde::__private::Ok(DecryptMessage)
                    }
                }
                _serde::Deserializer::deserialize_unit_struct(
                    __deserializer,
                    "DecryptMessage",
                    __Visitor {
                        marker: _serde::__private::PhantomData::<DecryptMessage>,
                        lifetime: _serde::__private::PhantomData,
                    },
                )
            }
        }
    };
    impl ::ludi::Message for DecryptMessage {
        type Return = ();
    }
    impl<A> ::ludi::Dispatch<A> for DecryptMessage
    where
        A: ::ludi::Actor + ::ludi::Handler<DecryptMessage>,
    {
        async fn dispatch<R: FnOnce(()) + Send>(
            self,
            actor: &mut A,
            ctx: &mut ::ludi::Context<A>,
            ret: R,
        ) {
            ::ludi::Handler::<DecryptMessage>::process(actor, self, ctx, ret).await;
        }
    }
    impl ::ludi::Handler<ComputeClientKey> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: ComputeClientKey,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <ComputeClientKey as ::ludi::Message>::Return {
            {
                ctx.try_or_stop(|_| self.compute_client_key()).await;
            }
        }
    }
    impl ::ludi::Handler<ComputeKeyExchange> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: ComputeKeyExchange,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <ComputeKeyExchange as ::ludi::Message>::Return {
            let ComputeKeyExchange { handshake_commitment } = msg;
            {
                ctx.try_or_stop(|_| self.compute_key_exchange(handshake_commitment))
                    .await;
            }
        }
    }
    impl ::ludi::Handler<ClientFinishedVd> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: ClientFinishedVd,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <ClientFinishedVd as ::ludi::Message>::Return {
            {
                ctx.try_or_stop(|_| self.client_finished_vd()).await;
            }
        }
    }
    impl ::ludi::Handler<ServerFinishedVd> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: ServerFinishedVd,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <ServerFinishedVd as ::ludi::Message>::Return {
            {
                ctx.try_or_stop(|_| self.server_finished_vd()).await;
            }
        }
    }
    impl ::ludi::Handler<EncryptClientFinished> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: EncryptClientFinished,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <EncryptClientFinished as ::ludi::Message>::Return {
            {
                ctx.try_or_stop(|_| self.encrypt_client_finished()).await;
            }
        }
    }
    impl ::ludi::Handler<EncryptAlert> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: EncryptAlert,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <EncryptAlert as ::ludi::Message>::Return {
            let EncryptAlert { msg } = msg;
            {
                ctx.try_or_stop(|_| self.encrypt_alert(msg)).await;
            }
        }
    }
    impl ::ludi::Handler<EncryptMessage> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: EncryptMessage,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <EncryptMessage as ::ludi::Message>::Return {
            let EncryptMessage { len } = msg;
            {
                ctx.try_or_stop(|_| self.encrypt_message(len)).await;
            }
        }
    }
    impl ::ludi::Handler<DecryptServerFinished> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: DecryptServerFinished,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <DecryptServerFinished as ::ludi::Message>::Return {
            let DecryptServerFinished { ciphertext } = msg;
            {
                ctx.try_or_stop(|_| self.decrypt_server_finished(ciphertext)).await;
            }
        }
    }
    impl ::ludi::Handler<DecryptAlert> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: DecryptAlert,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <DecryptAlert as ::ludi::Message>::Return {
            let DecryptAlert { ciphertext } = msg;
            {
                ctx.try_or_stop(|_| self.decrypt_alert(ciphertext)).await;
            }
        }
    }
    impl ::ludi::Handler<CommitMessage> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: CommitMessage,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <CommitMessage as ::ludi::Message>::Return {
            let CommitMessage { msg } = msg;
            {
                ctx.try_or_stop(|_| async { self.commit_message(msg) }).await;
            }
        }
    }
    impl ::ludi::Handler<DecryptMessage> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: DecryptMessage,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <DecryptMessage as ::ludi::Message>::Return {
            {
                ctx.try_or_stop(|_| self.decrypt_message()).await;
            }
        }
    }
    impl ::ludi::Handler<CloseConnection> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: CloseConnection,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <CloseConnection as ::ludi::Message>::Return {
            {
                ctx.try_or_stop(|_| async { self.close_connection() }).await;
                ctx.stop();
                Ok(())
            }
        }
    }
    impl ::ludi::Handler<Commit> for MpcTlsFollower {
        async fn handle(
            &mut self,
            msg: Commit,
            ctx: &mut ::ludi::Context<Self>,
        ) -> <Commit as ::ludi::Message>::Return {
            {
                ctx.try_or_stop(|_| self.commit()).await;
                Ok(())
            }
        }
    }
    mod state {
        use super::*;
        use enum_try_as_inner::EnumTryAsInner;
        #[derive_err(Debug)]
        pub(super) enum State {
            Init,
            ClientKey,
            Ke(Ke),
            Cf(Cf),
            Sf(Sf),
            Active(Active),
            Closed(Closed),
            Error,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for State {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                match self {
                    State::Init => ::core::fmt::Formatter::write_str(f, "Init"),
                    State::ClientKey => ::core::fmt::Formatter::write_str(f, "ClientKey"),
                    State::Ke(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Ke",
                            &__self_0,
                        )
                    }
                    State::Cf(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Cf",
                            &__self_0,
                        )
                    }
                    State::Sf(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Sf",
                            &__self_0,
                        )
                    }
                    State::Active(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Active",
                            &__self_0,
                        )
                    }
                    State::Closed(__self_0) => {
                        ::core::fmt::Formatter::debug_tuple_field1_finish(
                            f,
                            "Closed",
                            &__self_0,
                        )
                    }
                    State::Error => ::core::fmt::Formatter::write_str(f, "Error"),
                }
            }
        }
        impl State {
            ///Returns true if this is a `State::Init`, otherwise false
            #[inline]
            pub fn is_init(&self) -> bool {
                match self {
                    Self::Init => true,
                    _ => false,
                }
            }
            ///Returns references to the inner fields if this is a `State::Init`, otherwise an `StateError`
            #[inline]
            pub fn try_as_init(&self) -> ::core::result::Result<&(), StateError> {
                match self {
                    Self::Init => ::core::result::Result::Ok(&()),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Init",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::Init`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_init(self) -> ::core::result::Result<(), StateError> {
                match self {
                    Self::Init => ::core::result::Result::Ok(()),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Init",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            ///Returns true if this is a `State::ClientKey`, otherwise false
            #[inline]
            pub fn is_client_key(&self) -> bool {
                match self {
                    Self::ClientKey => true,
                    _ => false,
                }
            }
            ///Returns references to the inner fields if this is a `State::ClientKey`, otherwise an `StateError`
            #[inline]
            pub fn try_as_client_key(&self) -> ::core::result::Result<&(), StateError> {
                match self {
                    Self::ClientKey => ::core::result::Result::Ok(&()),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "ClientKey",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::ClientKey`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_client_key(self) -> ::core::result::Result<(), StateError> {
                match self {
                    Self::ClientKey => ::core::result::Result::Ok(()),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "ClientKey",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            ///Returns true if this is a `State::Ke`, otherwise false
            #[inline]
            #[allow(unused_variables)]
            pub fn is_ke(&self) -> bool {
                match self {
                    Self::Ke(inner) => true,
                    _ => false,
                }
            }
            ///Returns mutable references to the inner fields if this is a `State::Ke`, otherwise an `StateError`
            #[inline]
            pub fn try_as_ke_mut(
                &mut self,
            ) -> ::core::result::Result<&mut Ke, StateError> {
                match self {
                    Self::Ke(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Ke",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns references to the inner fields if this is a `State::Ke`, otherwise an `StateError`
            #[inline]
            pub fn try_as_ke(&self) -> ::core::result::Result<&Ke, StateError> {
                match self {
                    Self::Ke(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Ke",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::Ke`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_ke(self) -> ::core::result::Result<Ke, StateError> {
                match self {
                    Self::Ke(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Ke",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            ///Returns true if this is a `State::Cf`, otherwise false
            #[inline]
            #[allow(unused_variables)]
            pub fn is_cf(&self) -> bool {
                match self {
                    Self::Cf(inner) => true,
                    _ => false,
                }
            }
            ///Returns mutable references to the inner fields if this is a `State::Cf`, otherwise an `StateError`
            #[inline]
            pub fn try_as_cf_mut(
                &mut self,
            ) -> ::core::result::Result<&mut Cf, StateError> {
                match self {
                    Self::Cf(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Cf",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns references to the inner fields if this is a `State::Cf`, otherwise an `StateError`
            #[inline]
            pub fn try_as_cf(&self) -> ::core::result::Result<&Cf, StateError> {
                match self {
                    Self::Cf(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Cf",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::Cf`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_cf(self) -> ::core::result::Result<Cf, StateError> {
                match self {
                    Self::Cf(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Cf",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            ///Returns true if this is a `State::Sf`, otherwise false
            #[inline]
            #[allow(unused_variables)]
            pub fn is_sf(&self) -> bool {
                match self {
                    Self::Sf(inner) => true,
                    _ => false,
                }
            }
            ///Returns mutable references to the inner fields if this is a `State::Sf`, otherwise an `StateError`
            #[inline]
            pub fn try_as_sf_mut(
                &mut self,
            ) -> ::core::result::Result<&mut Sf, StateError> {
                match self {
                    Self::Sf(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Sf",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns references to the inner fields if this is a `State::Sf`, otherwise an `StateError`
            #[inline]
            pub fn try_as_sf(&self) -> ::core::result::Result<&Sf, StateError> {
                match self {
                    Self::Sf(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Sf",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::Sf`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_sf(self) -> ::core::result::Result<Sf, StateError> {
                match self {
                    Self::Sf(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Sf",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            ///Returns true if this is a `State::Active`, otherwise false
            #[inline]
            #[allow(unused_variables)]
            pub fn is_active(&self) -> bool {
                match self {
                    Self::Active(inner) => true,
                    _ => false,
                }
            }
            ///Returns mutable references to the inner fields if this is a `State::Active`, otherwise an `StateError`
            #[inline]
            pub fn try_as_active_mut(
                &mut self,
            ) -> ::core::result::Result<&mut Active, StateError> {
                match self {
                    Self::Active(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Active",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns references to the inner fields if this is a `State::Active`, otherwise an `StateError`
            #[inline]
            pub fn try_as_active(&self) -> ::core::result::Result<&Active, StateError> {
                match self {
                    Self::Active(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Active",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::Active`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_active(self) -> ::core::result::Result<Active, StateError> {
                match self {
                    Self::Active(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Active",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            ///Returns true if this is a `State::Closed`, otherwise false
            #[inline]
            #[allow(unused_variables)]
            pub fn is_closed(&self) -> bool {
                match self {
                    Self::Closed(inner) => true,
                    _ => false,
                }
            }
            ///Returns mutable references to the inner fields if this is a `State::Closed`, otherwise an `StateError`
            #[inline]
            pub fn try_as_closed_mut(
                &mut self,
            ) -> ::core::result::Result<&mut Closed, StateError> {
                match self {
                    Self::Closed(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Closed",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns references to the inner fields if this is a `State::Closed`, otherwise an `StateError`
            #[inline]
            pub fn try_as_closed(&self) -> ::core::result::Result<&Closed, StateError> {
                match self {
                    Self::Closed(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Closed",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::Closed`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_closed(self) -> ::core::result::Result<Closed, StateError> {
                match self {
                    Self::Closed(inner) => ::core::result::Result::Ok((inner)),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Closed",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            ///Returns true if this is a `State::Error`, otherwise false
            #[inline]
            pub fn is_error(&self) -> bool {
                match self {
                    Self::Error => true,
                    _ => false,
                }
            }
            ///Returns references to the inner fields if this is a `State::Error`, otherwise an `StateError`
            #[inline]
            pub fn try_as_error(&self) -> ::core::result::Result<&(), StateError> {
                match self {
                    Self::Error => ::core::result::Result::Ok(&()),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Error",
                                self.variant_name(),
                                ::core::option::Option::None,
                            ),
                        )
                    }
                }
            }
            ///Returns the inner fields if this is a `State::Error`, otherwise returns back the enum in the `Err` case of the result
            #[inline]
            pub fn try_into_error(self) -> ::core::result::Result<(), StateError> {
                match self {
                    Self::Error => ::core::result::Result::Ok(()),
                    _ => {
                        ::core::result::Result::Err(
                            StateError::new(
                                "Error",
                                self.variant_name(),
                                ::core::option::Option::Some(self),
                            ),
                        )
                    }
                }
            }
            /// Returns the name of the variant.
            fn variant_name(&self) -> &'static str {
                match self {
                    Self::Init => "Init",
                    Self::ClientKey => "ClientKey",
                    Self::Ke(..) => "Ke",
                    Self::Cf(..) => "Cf",
                    Self::Sf(..) => "Sf",
                    Self::Active(..) => "Active",
                    Self::Closed(..) => "Closed",
                    Self::Error => "Error",
                    _ => {
                        ::core::panicking::panic(
                            "internal error: entered unreachable code",
                        )
                    }
                }
            }
        }
        ///An error type for the `State::try_as_*` functions
        pub(super) struct StateError {
            expected: &'static str,
            actual: &'static str,
            value: ::core::option::Option<State>,
        }
        impl StateError {
            /// Creates a new error indicating the expected variant and the actual variant.
            fn new(
                expected: &'static str,
                actual: &'static str,
                value: ::core::option::Option<State>,
            ) -> Self {
                Self { expected, actual, value }
            }
            /// Returns the name of the variant that was expected.
            pub fn expected(&self) -> &'static str {
                self.expected
            }
            /// Returns the name of the actual variant.
            pub fn actual(&self) -> &'static str {
                self.actual
            }
            /// Returns a reference to the actual value, if present.
            pub fn value(&self) -> ::core::option::Option<&State> {
                self.value.as_ref()
            }
            /// Returns the actual value, if present.
            pub fn into_value(self) -> ::core::option::Option<State> {
                self.value
            }
        }
        impl ::core::fmt::Debug for StateError
        where
            State: ::core::fmt::Debug,
        {
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                f.debug_struct("StateError")
                    .field("expected", &self.expected)
                    .field("actual", &self.actual)
                    .field("value", &self.value)
                    .finish()
            }
        }
        impl ::core::fmt::Display for StateError {
            fn fmt(
                &self,
                formatter: &mut ::core::fmt::Formatter,
            ) -> ::core::fmt::Result {
                formatter
                    .write_fmt(
                        format_args!(
                            "expected State::{0}, but got State::{1}",
                            self.expected(),
                            self.actual(),
                        ),
                    )
            }
        }
        impl ::std::error::Error for StateError
        where
            State: ::core::fmt::Debug,
        {}
        impl State {
            pub(super) fn take(&mut self) -> Self {
                mem::replace(self, State::Error)
            }
        }
        impl From<StateError> for MpcTlsError {
            fn from(err: StateError) -> Self {
                MpcTlsError::new(Kind::State, err)
            }
        }
        pub(super) struct Ke {
            pub(super) handshake_commitment: Option<Hash>,
            pub(super) server_key: PublicKey,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Ke {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "Ke",
                    "handshake_commitment",
                    &self.handshake_commitment,
                    "server_key",
                    &&self.server_key,
                )
            }
        }
        pub(super) struct Cf {
            pub(super) handshake_commitment: Option<Hash>,
            pub(super) server_key: PublicKey,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Cf {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "Cf",
                    "handshake_commitment",
                    &self.handshake_commitment,
                    "server_key",
                    &&self.server_key,
                )
            }
        }
        pub(super) struct Sf {
            pub(super) handshake_commitment: Option<Hash>,
            pub(super) server_key: PublicKey,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Sf {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "Sf",
                    "handshake_commitment",
                    &self.handshake_commitment,
                    "server_key",
                    &&self.server_key,
                )
            }
        }
        pub(super) struct Active {
            pub(super) handshake_commitment: Option<Hash>,
            pub(super) server_key: PublicKey,
            /// TLS messages purportedly received by the leader from the server.
            ///
            /// The follower must verify the authenticity of these messages with AEAD verification
            /// (i.e. by verifying the authentication tag).
            pub(super) buffer: VecDeque<OpaqueMessage>,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Active {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field3_finish(
                    f,
                    "Active",
                    "handshake_commitment",
                    &self.handshake_commitment,
                    "server_key",
                    &self.server_key,
                    "buffer",
                    &&self.buffer,
                )
            }
        }
        pub(super) struct Closed {
            pub(super) handshake_commitment: Option<Hash>,
            pub(super) server_key: PublicKey,
        }
        #[automatically_derived]
        impl ::core::fmt::Debug for Closed {
            #[inline]
            fn fmt(&self, f: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
                ::core::fmt::Formatter::debug_struct_field2_finish(
                    f,
                    "Closed",
                    "handshake_commitment",
                    &self.handshake_commitment,
                    "server_key",
                    &&self.server_key,
                )
            }
        }
    }
    use state::*;
}
