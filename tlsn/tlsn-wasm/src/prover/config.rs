use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct ProverConfig {
    id: String,
    server_dns: String,
    max_sent_data: usize,
    max_received_data: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
#[non_exhaustive]
pub enum Body {
    Json(JsonValue),
}

#[derive(Serialize, Deserialize)]
#[serde(try_from = "String")]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

impl TryFrom<String> for Method {
    type Error = String;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.to_lowercase().as_str() {
            "get" => Ok(Method::Get),
            "post" => Ok(Method::Post),
            "put" => Ok(Method::Put),
            "delete" => Ok(Method::Delete),
            _ => Err(format!("invalid method: {}", value)),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct HttpRequest {
    method: Method,
    headers: HashMap<String, String>,
    body: Body,
}

#[derive(Serialize, Deserialize)]
pub struct HttpResponse {
    status: u16,
    headers: HashMap<String, String>,
    body: Body,
}
