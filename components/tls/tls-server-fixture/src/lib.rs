use async_rustls::{server::TlsStream, TlsAcceptor};
use futures::{AsyncRead, AsyncWrite, FutureExt, TryStreamExt};
use hyper::{server::conn::Http, service::service_fn, Body, Method, Request, Response, StatusCode};
use rustls::{Certificate, PrivateKey, ServerConfig};
use std::sync::Arc;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::Instrument;

/// A certificate authority certificate fixture.
pub static CA_CERT_DER: &[u8] = include_bytes!("rootCA.der");
/// A server certificate (domain=test-server.io) fixture.
pub static SERVER_CERT_DER: &[u8] = include_bytes!("domain.der");
/// A server private key fixture.
pub static SERVER_KEY_DER: &[u8] = include_bytes!("domain_key.der");
/// The domain name bound to the server certificate.
pub static SERVER_DOMAIN: &str = "test-server.io";

/// Binds a test server to the provided socket.
#[tracing::instrument(skip(socket))]
pub async fn bind_test_server<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    socket: T,
) -> Result<TlsStream<T>, hyper::Error> {
    let key = PrivateKey(SERVER_KEY_DER.to_vec());
    let cert = Certificate(SERVER_CERT_DER.to_vec());

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    let conn = acceptor.accept(socket).await.unwrap();

    tracing::debug!("starting HTTP server");

    Http::new()
        .http1_only(true)
        .http1_keep_alive(false)
        .serve_connection(conn.compat(), service_fn(echo))
        .without_shutdown()
        .map(|res| res.map(|parts| parts.io.into_inner()))
        .in_current_span()
        .await
}

#[tracing::instrument]
async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    match (req.method(), req.uri().path()) {
        // Serve some instructions at /
        (&Method::GET, "/") => Ok(Response::new(Body::from(
            "Try POSTing data to /echo such as: `curl localhost:3000/echo -XPOST -d 'hello world'`",
        ))),

        // Simply echo the body back to the client.
        (&Method::POST, "/echo") => Ok(Response::new(req.into_body())),

        // Convert to uppercase before sending back to client using a stream.
        (&Method::POST, "/echo/uppercase") => {
            let chunk_stream = req.into_body().map_ok(|chunk| {
                chunk
                    .iter()
                    .map(|byte| byte.to_ascii_uppercase())
                    .collect::<Vec<u8>>()
            });
            Ok(Response::new(Body::wrap_stream(chunk_stream)))
        }

        // Reverse the entire body before sending back to the client.
        //
        // Since we don't know the end yet, we can't simply stream
        // the chunks as they arrive as we did with the above uppercase endpoint.
        // So here we do `.await` on the future, waiting on concatenating the full body,
        // then afterwards the content can be reversed. Only then can we return a `Response`.
        (&Method::POST, "/echo/reversed") => {
            let whole_body = hyper::body::to_bytes(req.into_body()).await?;

            let reversed_body = whole_body.iter().rev().cloned().collect::<Vec<u8>>();
            Ok(Response::new(Body::from(reversed_body)))
        }

        // Return the 404 Not Found for other routes.
        _ => {
            let mut not_found = Response::default();
            *not_found.status_mut() = StatusCode::NOT_FOUND;
            Ok(not_found)
        }
    }
}
