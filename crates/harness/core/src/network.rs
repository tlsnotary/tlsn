use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};

pub const PORT_PROTO: u16 = 8000;
pub const PORT_APP_SERVER: u16 = 8000;
pub const PORT_PROXY: u16 = 8000;
pub const PORT_WASM_SERVER: u16 = 8080;
pub const PORT_RPC: u16 = 8000;
pub const PORT_BROWSER: u16 = 8001;
pub const NS_0: &str = "tlsn-ns0";
pub const NS_1: &str = "tlsn-ns1";
pub const NS_APP: &str = "tlsn-nsapp";
pub const BRIDGE: &str = "tlsn-br";
pub const VETH_PROTO_0: &str = "tlsn-vethp0";
pub const VETH_PROTO_1: &str = "tlsn-vethp1";
pub const VETH_RPC_0: &str = "tlsn-vethr0";
pub const VETH_RPC_1: &str = "tlsn-vethr1";
pub const VETH_PROTO_PROXY: &str = "tlsn-vethppx";
pub const VETH_APP_PROXY: &str = "tlsn-vethapx";
pub const VETH_APP: &str = "tlsn-vethapp";
pub const VETH_APP_0: &str = "tlsn-vethapp0";
pub const VETH_APP_1: &str = "tlsn-vethapp1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub subnet: Ipv4Net,
    pub wasm: (Ipv4Addr, u16),
    pub host: Ipv4Addr,
    pub proto_proxy: (Ipv4Addr, u16),
    pub app_proxy: (Ipv4Addr, u16),
    pub rpc_0: (Ipv4Addr, u16),
    pub rpc_1: (Ipv4Addr, u16),
    pub proto_0: (Ipv4Addr, u16),
    pub proto_1: (Ipv4Addr, u16),
    pub app: (Ipv4Addr, u16),
    pub app_0: Ipv4Addr,
    pub app_1: Ipv4Addr,
}

impl NetworkConfig {
    pub fn new(subnet: Ipv4Net) -> Self {
        let mut hosts = subnet.hosts();
        Self {
            subnet,
            host: hosts.next().unwrap(),
            wasm: (Ipv4Addr::new(127, 0, 0, 1), PORT_WASM_SERVER),
            proto_proxy: (hosts.next().unwrap(), PORT_PROXY),
            app_proxy: (hosts.next().unwrap(), PORT_PROXY),
            rpc_0: (hosts.next().unwrap(), PORT_RPC),
            rpc_1: (hosts.next().unwrap(), PORT_RPC),
            proto_0: (hosts.next().unwrap(), PORT_PROTO),
            proto_1: (hosts.next().unwrap(), PORT_PROTO),
            app: (hosts.next().unwrap(), PORT_APP_SERVER),
            app_0: hosts.next().unwrap(),
            app_1: hosts.next().unwrap(),
        }
    }
}
