use std::time::Instant;

use tlsn_benches_library::{run_prover, AsyncIo, ProverTrait};

use async_trait::async_trait;

pub struct NativeProver {
    upload_size: usize,
    download_size: usize,
    defer_decryption: bool,
    io: Option<Box<dyn AsyncIo>>,
    client_conn: Option<Box<dyn AsyncIo>>,
}

#[async_trait]
impl ProverTrait for NativeProver {
    async fn setup(
        upload_size: usize,
        download_size: usize,
        defer_decryption: bool,
        io: Box<dyn AsyncIo>,
        client_conn: Box<dyn AsyncIo>,
    ) -> anyhow::Result<Self>
    where
        Self: Sized,
    {
        Ok(Self {
            upload_size,
            download_size,
            defer_decryption,
            io: Some(io),
            client_conn: Some(client_conn),
        })
    }

    async fn run(&mut self) -> anyhow::Result<u64> {
        let io = std::mem::take(&mut self.io).unwrap();
        let client_conn = std::mem::take(&mut self.client_conn).unwrap();

        let start_time = Instant::now();

        run_prover(
            self.upload_size,
            self.download_size,
            self.defer_decryption,
            io,
            client_conn,
        )
        .await?;

        Ok(Instant::now().duration_since(start_time).as_secs())
    }
}
