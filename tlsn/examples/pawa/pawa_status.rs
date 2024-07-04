use dotenv::dotenv;
use std::{env, io::{self, Write}, sync::Arc};
use tokio::{io::AsyncWriteExt as _, sync::Mutex};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

#[tokio::main]
async fn main() -> std::io::Result<()> {
    print!("Enter payout id: ");
    io::stdout().flush().expect("Failed to flush stdout");

    let mut payout_id = String::new();
    io::stdin().read_line(&mut payout_id).expect("Failed to read line");

    let payout_id = payout_id.trim();

    println!("Payout ID: {}", payout_id);
    dotenv().ok();

    let jwt = env::var("JWT").expect("JWT must be set");

    const NOTARY_HOST: &str = "notary.pse.dev";
    const NOTARY_PORT: u16 = 443;

    let notary_client = NotaryClient::builder().host(NOTARY_HOST).port(NOTARY_PORT).enable_tls(true).build().unwrap();
    info!("Created Notary Client");
    Ok(())

}