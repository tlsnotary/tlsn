use dotenv::dotenv;
use std::{env, io::Write, sync::Arc};
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
    let payout_id = env::var("PAYOUT_ID").expect("PAYOUT_ID must be set");
}