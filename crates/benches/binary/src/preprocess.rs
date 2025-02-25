use hmac_sha256::build_circuits;

pub async fn preprocess_prf_circuits() {
    build_circuits().await;
}
