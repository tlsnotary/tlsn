use tls_client::ServerName;

pub struct Config {
    server_name: ServerName,
}

pub struct ConfigBuilder<State> {
    state: State,
}
