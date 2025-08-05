use serde::{Deserialize, Serialize};

wit_bindgen::generate!({
    path: "wit/world.wit",
    async: true
});

struct Component;

#[derive(Deserialize)]
struct Input {
    id: u8
}

#[derive(Serialize)]
struct Output {
    result: bool
}

impl Guest for Component {
    async fn main(input: Vec<u8>) -> Vec<u8> {
        let input: Input = serde_json::from_slice(&input).unwrap();
        let payload_bytes = read(input.id).await;
        let result_bytes = write(payload_bytes).await;
        let result: bool = serde_json::from_slice(&result_bytes).unwrap();
        let output = Output { result };
        serde_json::to_vec(&output).unwrap()
    }
}

export!(Component);
