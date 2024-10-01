//! A TLS server fixture for testing

#![deny(missing_docs, unreachable_pub, unused_must_use)]
#![deny(clippy::all)]
#![forbid(unsafe_code)]

use bytes::Bytes;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use futures_rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    rustls::ServerConfig,
    TlsAcceptor,
};
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{
    body::{Frame, Incoming},
    server::conn::http1,
    service::service_fn,
    Method, Request, Response, StatusCode,
};
use hyper_util::rt::TokioIo;
use std::{io::Write, sync::Arc};
use tokio_util::{
    compat::{Compat, FuturesAsyncReadCompatExt},
    io::SyncIoBridge,
};
use tracing::Instrument;

/// A certificate authority certificate fixture.
pub static CA_CERT_DER: &[u8] = include_bytes!("root_ca_cert.der");
/// A server certificate (domain=test-server.io) fixture.
pub static SERVER_CERT_DER: &[u8] = include_bytes!("test_server_cert.der");
/// A server private key fixture.
pub static SERVER_KEY_DER: &[u8] = include_bytes!("test_server_private_key.der");
/// The domain name bound to the server certificate.
pub static SERVER_DOMAIN: &str = "test-server.io";
/// The length of an application record expected by the test TLS server.
pub static APP_RECORD_LENGTH: usize = 1024;
/// How many ms to delay before closing the socket
pub static CLOSE_DELAY: u64 = 1000;

/// Binds a `hyper::server` test server to the provided socket.
#[tracing::instrument(skip(socket))]
pub async fn bind_test_server_hyper<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
) -> Result<(), hyper::Error> {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = CertificateDer::from(SERVER_CERT_DER);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let conn = acceptor.accept(socket).await.unwrap();

    let io = TokioIo::new(conn.compat());

    tracing::debug!("starting HTTP server");

    http1::Builder::new()
        .keep_alive(true)
        .serve_connection(io, service_fn(echo))
        .in_current_span()
        .await
}

/// Binds a raw TLS test server to the provided socket.
#[tracing::instrument(skip(socket))]
pub async fn bind_test_server<
    T: tokio::io::AsyncWrite + tokio::io::AsyncRead + Send + Unpin + 'static,
>(
    socket: Compat<T>,
) {
    let key = PrivateKeyDer::Pkcs8(SERVER_KEY_DER.into());
    let cert = CertificateDer::from(SERVER_CERT_DER);

    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let mut conn = acceptor.accept(socket).await.unwrap();

    tracing::debug!("TLS server will serve one connection");
    let mut must_delay_when_closing = false;

    loop {
        let mut read_buf = vec![0u8; APP_RECORD_LENGTH];
        if conn.read_exact(&mut read_buf).await.is_err() {
            // EOF reached because client closed its tx part of the socket.
            // The client's rx part of the socket is still open and waiting for a clean
            // server shutdown.
            if must_delay_when_closing {
                // delay closing the socket
                tokio::time::sleep(std::time::Duration::from_millis(CLOSE_DELAY)).await;
            }
            break;
        }
        let s = std::str::from_utf8(&read_buf).unwrap();
        // remove padding zero bytes
        let s = s.replace('\0', "");
        let s = s.as_str();

        match s {
            "must_delay_when_closing" => {
                // don't close the socket immediately
                must_delay_when_closing = true;
            }
            "send_close_notify" => {
                // only send close_notify but don't close the socket

                let (socket, mut tls) = conn.into_inner();

                // spawning because SyncIoBridge must be used on a separate thread
                tokio::task::spawn_blocking(move || {
                    // give the client some time (e.g. to send their close_notify)
                    std::thread::sleep(std::time::Duration::from_millis(10));

                    // wrap in `SyncIoBridge` since `socket` must be `io::Write`
                    let mut socket = SyncIoBridge::new(socket.into_inner());
                    tls.send_close_notify();
                    tls.write_tls(&mut socket).unwrap();
                    socket.flush().unwrap();
                })
                .await
                .unwrap();
                break;
            }
            "send_close_notify_and_close_socket" => {
                // send close_notify AND close the socket

                let (socket, mut tls) = conn.into_inner();

                // spawning because SyncIoBridge must be used on a separate thread
                tokio::task::spawn_blocking(move || {
                    // give the client some time (e.g. to send their close_notify)
                    std::thread::sleep(std::time::Duration::from_millis(10));

                    // wrap in `SyncIoBridge` since `socket` must be `io::Write`
                    let mut socket = SyncIoBridge::new(socket.into_inner());

                    tls.send_close_notify();
                    tls.write_tls(&mut socket).unwrap();
                    socket.flush().unwrap();
                    socket.shutdown().unwrap();
                })
                .await
                .unwrap();
                break;
            }
            "close_socket" => {
                // close the socket without sending close_notify

                let (mut socket, _tls) = conn.into_inner();
                socket.close().await.unwrap();
                break;
            }
            "send_corrupted_message" => {
                // send a corrupted message

                let (socket, _tls) = conn.into_inner();

                // spawning because SyncIoBridge must be used on a separate thread
                tokio::task::spawn_blocking(move || {
                    // wrap in `SyncIoBridge` since `socket` must be `io::Write`
                    let mut socket = SyncIoBridge::new(socket.into_inner());

                    // write random bytes
                    socket.write_all(&[1u8; 18]).unwrap();
                    socket.flush().unwrap();
                })
                .await
                .unwrap();
                break;
            }
            "send_record_with_bad_mac" => {
                // send a record which a bad MAC which will trigger the `bad_record_mac` alert
                // on the client side

                let (socket, _tls) = conn.into_inner();

                // spawning because `SyncIoBridge` must be used on a separate thread
                tokio::task::spawn_blocking(move || {
                    // wrap in `SyncIoBridge` since `socket` must be `io::Write`
                    let mut socket = SyncIoBridge::new(socket.into_inner());

                    let mut record = Vec::new();
                    record.extend(vec![0x17, 0x03, 0x03, 0, 30]);
                    record.extend(vec![1u8; 30]);

                    socket.write_all(&record).unwrap();
                    socket.flush().unwrap();
                })
                .await
                .unwrap();
                break;
            }
            "send_alert" => {
                // send a `bad_record_mac` alert to the client

                let (socket, mut tls) = conn.into_inner();

                // spawning because SyncIoBridge must be used on a separate thread
                tokio::task::spawn_blocking(move || {
                    // create a record with a bad MAC and feed to the server's TLS connection
                    let mut record = Vec::new();
                    record.extend(vec![0x17, 0x03, 0x03, 0, 30]);
                    record.extend(vec![1u8; 30]);
                    tls.read_tls(&mut record.as_slice()).unwrap();

                    // ignore the error due to the bad MAC. An alert message will be created
                    assert!(tls.process_new_packets().is_err());

                    // wrap in `SyncIoBridge` since `socket` must be `io::Write`
                    let mut socket = SyncIoBridge::new(socket.into_inner());

                    // write the alert message to the socket
                    tls.write_tls(&mut socket).unwrap();
                    socket.flush().unwrap();
                })
                .await
                .unwrap();
                break;
            }
            _ => {
                // for any other request, just send back "hello" and keep looping
                conn.write_all("hello".as_bytes()).await.unwrap();
                conn.flush().await.unwrap();
            }
        }
    }
}

// Adapted from https://github.com/hyperium/hyper/blob/721785efad8537513e48d900a85c05ce79483018/examples/echo.rs
#[tracing::instrument]
async fn echo(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => Ok(Response::new(full(
            "Try POSTing data to /echo such as: `curl localhost:3000/echo -XPOST -d 'hello world'`",
        ))),

        // Simply echo the body back to the client.
        (&Method::POST, "/echo") => Ok(Response::new(req.into_body().boxed())),

        // Convert to uppercase before sending back to client using a stream.
        (&Method::POST, "/echo/uppercase") => {
            let frame_stream = req.into_body().map_frame(|frame| {
                let frame = if let Ok(data) = frame.into_data() {
                    data.iter()
                        .map(|byte| byte.to_ascii_uppercase())
                        .collect::<Bytes>()
                } else {
                    Bytes::new()
                };

                Frame::data(frame)
            });

            Ok(Response::new(frame_stream.boxed()))
        }

        // Reverse the entire body before sending back to the client.
        //
        // Since we don't know the end yet, we can't simply stream
        // the chunks as they arrive as we did with the above uppercase endpoint.
        // So here we do `.await` on the future, waiting on concatenating the full body,
        // then afterwards the content can be reversed. Only then can we return a `Response`.
        (&Method::POST, "/echo/reversed") => {
            let whole_body = req.collect().await?.to_bytes();

            let reversed_body = whole_body.iter().rev().cloned().collect::<Vec<u8>>();
            Ok(Response::new(full(reversed_body)))
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::new(empty());
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}

fn full<T: Into<Bytes>>(chunk: T) -> BoxBody<Bytes, hyper::Error> {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}
