use futures::{
    AsyncReadExt, AsyncWriteExt,
    future::poll_fn,
    io::copy,
};
use tlsn_mux::{Config, Connection, ConnectionError};

use crate::{IoProvider, spawn};

// Number of concurrent streams opened on each side.
const N_STREAMS: usize = 64;
// Payload written on each stream by the prover and echoed by the verifier.
const PAYLOAD: &[u8] = b"mux-syn-opener";

crate::test!("mux_streams", prover_mux_streams, verifier_mux_streams);

async fn prover_mux_streams(provider: &IoProvider) {
    let io = provider.provide_proto_io().await.unwrap();

    let mut cfg = Config::default();
    cfg.set_max_num_streams(N_STREAMS);

    let mut conn = Connection::new(io, cfg);

    let mut streams = Vec::new();
    for i in 0..N_STREAMS {
        let id = format!("mux-stream-{i}");
        streams.push(conn.new_stream(id.as_bytes()).unwrap());
    }

    _ = spawn(poll_fn(move |cx| conn.poll(cx)));

    let mut tasks = Vec::new();
    for mut stream in streams {
        tasks.push(spawn(async move {
            let (mut r, mut w) = AsyncReadExt::split(&mut stream);
            let write_fut = w.write_all(PAYLOAD);
            let mut buf = vec![0; PAYLOAD.len()];
            let read_fut = r.read_exact(&mut buf);
            let (write_res, read_res) = futures::future::join(write_fut, read_fut).await;
            write_res?;
            read_res?;
            assert_eq!(buf, PAYLOAD);
            drop((r, w));
            stream.close().await?;
            Ok::<_, ConnectionError>(())
        }));
    }

    for task in tasks {
        task.await.unwrap().unwrap();
    }
}

async fn verifier_mux_streams(provider: &IoProvider) {
    let io = provider.provide_proto_io().await.unwrap();

    let mut cfg = Config::default();
    cfg.set_max_num_streams(N_STREAMS);

    let mut conn = Connection::new(io, cfg);

    let mut streams = Vec::new();
    for i in 0..N_STREAMS {
        let id = format!("mux-stream-{i}");
        streams.push(conn.new_stream(id.as_bytes()).unwrap());
    }

    _ = spawn(poll_fn(move |cx| conn.poll(cx)));

    let mut tasks = Vec::new();
    for mut stream in streams {
        tasks.push(spawn(async move {
            let (mut r, mut w) = AsyncReadExt::split(&mut stream);
            copy(&mut r, &mut w).await?;
            drop((r, w));
            stream.close().await?;
            Ok::<_, ConnectionError>(())
        }));
    }

    for task in tasks {
        task.await.unwrap().unwrap();
    }
}