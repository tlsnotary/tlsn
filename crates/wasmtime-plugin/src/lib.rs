use core::slice;
use http_body_util::Empty;
use hyper::{body::Bytes, client::conn::http1, Request, StatusCode};
use serde::{Deserialize, Serialize};
use wit_bindgen::spawn;
use std::{pin::Pin, task::{Context, Poll}};

use crate::component::wasmtime_plugin::io::NetworkIo;

wit_bindgen::generate!({
    path: "wit/plugin.wit",
    async: true
});

struct Component;

#[derive(Deserialize)]
struct Input {
    host: String,
    port: u32,
}

#[derive(Serialize)]
struct Output {
    result: bool
}

struct HyperIo {
    inner: NetworkIo
}

impl hyper::rt::Write for HyperIo
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let fut = self.inner.write(buf.to_vec());
        match std::pin::pin!(fut).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(n) => {
                std::task::Poll::Ready(Ok(n as usize))
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>
    ) -> Poll<Result<(), std::io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let fut = self.inner.shutdown();
        match std::pin::pin!(fut).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(_) => std::task::Poll::Ready(Ok(()))
        }
    }
}

impl hyper::rt::Read for HyperIo
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let buf_len = unsafe { buf.as_mut().len() };
        let buf_slice = unsafe {
            slice::from_raw_parts_mut(buf.as_mut().as_mut_ptr() as *mut u8, buf_len)
        };
        let fut = self.inner.read(buf_len as u32);
        match std::pin::pin!(fut).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(bytes) => {
                let n = bytes.len().min(buf_len);
                buf_slice[..n].copy_from_slice(&bytes[..n]);
                unsafe {
                    buf.advance(n);
                }
                std::task::Poll::Ready(Ok(()))
            }
        }
    }
}

impl Guest for Component {
    async fn main(input: Vec<u8>) -> Vec<u8> {
        let input: Input = serde_json::from_slice(&input).unwrap();

        let io = NetworkIo::new(input.host, input.port).await;
        let conn = HyperIo { inner: io };

        let (mut request_sender, conn) = http1::handshake(conn).await.unwrap();

        spawn(async move { conn.await.expect("connection should finish") });

        let request_builder = Request::builder()
            .uri("/");
        let request = request_builder.body(Empty::<Bytes>::new()).unwrap();

        let response = request_sender.send_request(request).await.unwrap();
        assert!(response.status() == StatusCode::OK);

        let output = Output { result: true };
        serde_json::to_vec(&output).unwrap()
    }
}

export!(Component);
