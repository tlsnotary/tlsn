use std::net::Ipv4Addr;

use anyhow::Result;

use harness_core::network::*;

pub struct Network {
    config: NetworkConfig,
    ns_0: Namespace,
    ns_1: Namespace,
    ns_app: Namespace,
    bridge: Bridge,
    veth_rpc_0: VethPair,
    veth_rpc_1: VethPair,
    veth_proto_0: VethPair,
    veth_proto_1: VethPair,
    veth_proto_proxy: VethPair,
    veth_app_proxy: VethPair,
    veth_app: VethPair,
    veth_app_0: VethPair,
    veth_app_1: VethPair,
}

impl Network {
    pub fn new(config: NetworkConfig) -> Result<Self> {
        let ns_0 = Namespace::new(NS_0);
        let ns_1 = Namespace::new(NS_1);
        let ns_app = Namespace::new(NS_APP);
        let mut bridge = Bridge::new(BRIDGE);
        let mut veth_rpc_0 = VethPair::new(VETH_RPC_0);
        let mut veth_rpc_1 = VethPair::new(VETH_RPC_1);
        let mut veth_proto_0 = VethPair::new(VETH_PROTO_0);
        let mut veth_proto_1 = VethPair::new(VETH_PROTO_1);
        let mut veth_proto_proxy = VethPair::new(VETH_PROTO_PROXY);
        let mut veth_app_proxy = VethPair::new(VETH_APP_PROXY);
        let mut veth_app = VethPair::new(VETH_APP);
        let mut veth_app_0 = VethPair::new(VETH_APP_0);
        let mut veth_app_1 = VethPair::new(VETH_APP_1);

        veth_rpc_0.0.set_namespace(&ns_0);
        veth_proto_0.0.set_namespace(&ns_0);
        veth_rpc_1.0.set_namespace(&ns_1);
        veth_proto_1.0.set_namespace(&ns_1);
        veth_app.0.set_namespace(&ns_app);
        veth_app_0.0.set_namespace(&ns_0);
        veth_app_1.0.set_namespace(&ns_1);

        // Assign addresses.
        let prefix_len = config.subnet.prefix_len();
        bridge.set_addr(config.host, prefix_len);
        veth_rpc_0.0.set_addr(config.rpc_0.0, prefix_len);
        veth_rpc_1.0.set_addr(config.rpc_1.0, prefix_len);
        veth_proto_0.0.set_addr(config.proto_0.0, prefix_len);
        veth_proto_1.0.set_addr(config.proto_1.0, prefix_len);
        veth_proto_proxy
            .0
            .set_addr(config.proto_proxy.0, prefix_len);
        veth_app_proxy.0.set_addr(config.app_proxy.0, prefix_len);
        veth_app.0.set_addr(config.app.0, prefix_len);

        Ok(Self {
            config,
            ns_0,
            ns_1,
            ns_app,
            bridge,
            veth_rpc_0,
            veth_rpc_1,
            veth_proto_0,
            veth_proto_1,
            veth_proto_proxy,
            veth_app_proxy,
            veth_app,
            veth_app_0,
            veth_app_1,
        })
    }

    /// Creates the network.
    pub fn create(&mut self) -> Result<()> {
        self.ns_0.create()?;
        self.ns_1.create()?;
        self.ns_app.create()?;
        self.bridge.create()?;
        self.veth_rpc_0.create()?;
        self.veth_rpc_1.create()?;
        self.veth_proto_0.create()?;
        self.veth_proto_1.create()?;
        self.veth_proto_proxy.create()?;
        self.veth_app_proxy.create()?;
        self.veth_app.create()?;
        self.veth_app_0.create()?;
        self.veth_app_1.create()?;

        // Enslave ends of the veth pairs to the bridge.
        self.bridge.add_interface(&self.veth_rpc_0.1)?;
        self.bridge.add_interface(&self.veth_rpc_1.1)?;
        self.bridge.add_interface(&self.veth_proto_0.1)?;
        self.bridge.add_interface(&self.veth_proto_1.1)?;
        self.bridge.add_interface(&self.veth_proto_proxy.1)?;
        self.bridge.add_interface(&self.veth_app_proxy.1)?;
        self.bridge.add_interface(&self.veth_app.1)?;
        self.bridge.add_interface(&self.veth_app_0.1)?;
        self.bridge.add_interface(&self.veth_app_1.1)?;

        // Bring up interfaces.
        self.bridge.up()?;
        self.veth_rpc_0.0.up()?;
        self.veth_rpc_0.1.up()?;
        self.veth_proto_0.0.up()?;
        self.veth_proto_0.1.up()?;
        self.veth_rpc_1.0.up()?;
        self.veth_rpc_1.1.up()?;
        self.veth_proto_1.0.up()?;
        self.veth_proto_1.1.up()?;
        self.veth_proto_proxy.0.up()?;
        self.veth_proto_proxy.1.up()?;
        self.veth_app_proxy.0.up()?;
        self.veth_app_proxy.1.up()?;
        self.veth_app.0.up()?;
        self.veth_app.1.up()?;
        self.veth_app_0.0.up()?;
        self.veth_app_0.1.up()?;
        self.veth_app_1.0.up()?;
        self.veth_app_1.1.up()?;

        duct::cmd!(
            "sudo",
            "ip",
            "netns",
            "exec",
            &self.ns_0.name,
            "ip",
            "link",
            "set",
            "lo",
            "up"
        )
        .run()?;

        ip_route(&self.ns_0, "default", &self.veth_rpc_0.0.name)?;
        ip_route(&self.ns_1, "default", &self.veth_rpc_1.0.name)?;
        ip_route(&self.ns_app, "default", &self.veth_app.0.name)?;
        ip_route(&self.ns_0, self.config.proto_1.0, &self.veth_proto_0.0.name)?;
        ip_route(&self.ns_1, self.config.proto_0.0, &self.veth_proto_1.0.name)?;
        ip_route(&self.ns_0, self.config.app.0, &self.veth_app_0.0.name)?;
        ip_route(&self.ns_1, self.config.app.0, &self.veth_app_1.0.name)?;
        ip_route(
            &self.ns_0,
            self.config.proto_proxy.0,
            &self.veth_proto_0.0.name,
        )?;
        ip_route(
            &self.ns_1,
            self.config.proto_proxy.0,
            &self.veth_proto_1.0.name,
        )?;
        ip_route(&self.ns_0, self.config.app_proxy.0, &self.veth_app_0.0.name)?;
        ip_route(&self.ns_1, self.config.app_proxy.0, &self.veth_app_1.0.name)?;

        ip_forward(
            &self.ns_0,
            (self.config.rpc_0.0, PORT_BROWSER),
            ("127.0.0.1", PORT_BROWSER),
        )?;

        Ok(())
    }

    /// Returns namespace 0.
    pub fn ns_0(&self) -> &Namespace {
        &self.ns_0
    }

    /// Returns namespace 1.
    pub fn ns_1(&self) -> &Namespace {
        &self.ns_1
    }

    /// Returns namespace app.
    pub fn ns_app(&self) -> &Namespace {
        &self.ns_app
    }

    pub fn print_network(&self) {
        println!("host: {}", self.config.host);
        println!(
            "protocol proxy: {}:{}",
            self.config.proto_proxy.0, self.config.proto_proxy.1
        );
        println!(
            "app proxy: {}:{}",
            self.config.app_proxy.0, self.config.app_proxy.1
        );
        println!(
            "executor 0 rpc: {}:{}",
            self.config.rpc_0.0, self.config.rpc_0.1
        );
        println!(
            "executor 1 rpc: {}:{}",
            self.config.rpc_1.0, self.config.rpc_1.1
        );
        println!(
            "protocol 0: {}:{}",
            self.config.proto_0.0, self.config.proto_0.1
        );
        println!(
            "protocol 1: {}:{}",
            self.config.proto_1.0, self.config.proto_1.1
        );
        println!("app: {}:{}", self.config.app.0, self.config.app.1);
    }

    /// Sets the configuration of the protocol interfaces.
    pub fn set_proto_config(&self, bandwidth: usize, delay: usize) -> Result<()> {
        self.veth_proto_0.0.set_egress(bandwidth, delay)?;
        self.veth_proto_1.0.set_egress(bandwidth, delay)?;

        Ok(())
    }

    /// Sets the configuration of the app interfaces.
    pub fn set_app_config(&self, bandwidth: usize, delay: usize) -> Result<()> {
        self.veth_app.0.set_egress(bandwidth, delay)?;
        self.veth_app_0.0.set_egress(bandwidth, delay)?;
        self.veth_app_1.0.set_egress(bandwidth, delay)?;

        Ok(())
    }

    /// Deletes the network.
    pub fn delete(&self) -> Result<()> {
        self.ns_0.delete()?;
        self.ns_1.delete()?;
        self.ns_app.delete()?;
        self.bridge.delete()?;
        self.veth_proto_proxy.delete()?;
        self.veth_app_proxy.delete()?;
        self.veth_app_0.delete()?;
        self.veth_app_1.delete()?;
        self.veth_app.delete()?;
        Ok(())
    }
}

// Runs a command in the namespace if it exists, otherwise runs it in the
// current namespace.
macro_rules! ns_cmd {
    ("sudo", $cmd:expr, $($args:expr),* => $namespace:expr)  => {
        if let Some(namespace) = $namespace.as_ref() {
            duct::cmd!(
                "sudo",
                "ip",
                "netns",
                "exec",
                namespace.name(),
                $cmd, $($args),*)
        } else {
            duct::cmd!("sudo", $cmd, $($args),*)
        }
    };
}

#[derive(Debug, Clone)]
pub struct Namespace {
    name: String,
}

impl Namespace {
    /// Creates a new namespace.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
        }
    }

    /// Returns the name of the namespace.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Creates the namespace.
    fn create(&self) -> Result<()> {
        let output = duct::cmd!("sudo", "ip", "netns", "add", &self.name)
            .stderr_capture()
            .unchecked()
            .run()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // If the namespace already exists, delete it.
            if stderr.contains("File exists") {
                duct::cmd!("sudo", "ip", "netns", "delete", &self.name).run()?;

                // Recreate the namespace.
                return self.create();
            }
        }

        Ok(())
    }

    /// Deletes the namespace.
    fn delete(&self) -> Result<()> {
        let output = duct::cmd!("sudo", "ip", "netns", "delete", &self.name)
            .stderr_capture()
            .unchecked()
            .run()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Ignore error if the namespace doesn't exist.
            if !stderr.contains("No such file or directory") {
                return Err(anyhow::anyhow!(
                    "Failed to delete namespace {}: {}",
                    self.name,
                    stderr
                ));
            }
        }

        Ok(())
    }
}

struct VethPair(Veth, Veth);

impl VethPair {
    fn new(name: &str) -> Self {
        Self(
            Veth::new(&format!("{}-0", name)),
            Veth::new(&format!("{}-1", name)),
        )
    }

    fn create(&self) -> Result<()> {
        let output = duct::cmd!(
            "sudo",
            "ip",
            "link",
            "add",
            &self.0.name,
            "type",
            "veth",
            "peer",
            "name",
            &self.1.name
        )
        .stderr_capture()
        .unchecked()
        .run()?;

        // Delete it if it already exists.
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stderr.contains("File exists") {
                self.delete()?;
                return self.create();
            } else {
                return Err(anyhow::anyhow!(
                    "Failed to create veth pair {}: {}",
                    self.0.name,
                    stderr
                ));
            }
        }

        self.0.create()?;
        self.1.create()?;

        Ok(())
    }

    fn delete(&self) -> Result<()> {
        self.0.delete()?;
        self.1.delete()?;

        Ok(())
    }
}

struct Veth {
    name: String,
    ns: Option<Namespace>,
    addr: Option<(Ipv4Addr, u8)>,
}

impl Veth {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ns: None,
            addr: None,
        }
    }

    fn create(&self) -> Result<()> {
        // Set namespace.
        if let Some(ns) = &self.ns {
            duct::cmd!("sudo", "ip", "link", "set", &self.name, "netns", ns.name()).run()?;
        }

        // Set address.
        if let Some((addr, prefix_length)) = &self.addr {
            ns_cmd!(
                "sudo",
                "ip",
                "addr",
                "add",
                format!("{}/{}", addr, prefix_length),
                "dev",
                &self.name
                => self.ns
            )
            .run()?;
        }

        Ok(())
    }

    /// Sets the namespace of the veth interface.
    fn set_namespace(&mut self, ns: &Namespace) {
        self.ns = Some(ns.clone());
    }

    /// Sets the address of the veth interface.
    fn set_addr(&mut self, addr: Ipv4Addr, prefix_length: u8) {
        self.addr = Some((addr, prefix_length));
    }

    /// Brings the veth interface up.
    fn up(&self) -> Result<()> {
        ns_cmd!(
            "sudo",
            "ip",
            "link",
            "set",
            &self.name,
            "up"
            => self.ns
        )
        .run()?;

        Ok(())
    }

    /// Sets the egress bandwidth and delay of the veth interface.
    ///
    /// # Arguments
    ///
    /// * `bandwidth` - Egress bandwidth in Mbps.
    /// * `delay` - Egress delay in ms.
    fn set_egress(&self, bandwidth: usize, delay: usize) -> Result<()> {
        // Remove existing rules.
        ns_cmd!(
            "sudo",
            "tc",
            "qdisc",
            "del",
            "dev",
            &self.name, "root"
            => self.ns
        )
        .stderr_capture()
        .unchecked()
        .run()?;

        if bandwidth > 0 {
            // Set burst to bandwidth delay product in kbit.
            let burst = bandwidth * (2 * delay.min(10));

            ns_cmd!(
                "sudo",
                "tc",
                "qdisc",
                "add",
                "dev",
                &self.name,
                "root",
                "handle",
                "1:",
                "tbf",
                "rate",
                format!("{bandwidth}mbit"),
                "burst",
                format!("{burst}kbit"),
                "latency",
                format!("60s")
                => self.ns
            )
            .run()?;
        }

        if delay > 0 {
            if bandwidth > 0 {
                ns_cmd!(
                    "sudo",
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    &self.name,
                    "parent",
                    "1:1",
                    "handle",
                    "10:",
                    "netem",
                    "delay",
                    format!("{delay}ms")
                    => self.ns
                )
                .run()?;
            } else {
                ns_cmd!(
                    "sudo",
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    &self.name,
                    "root",
                    "handle",
                    "1:",
                    "netem",
                    "delay",
                    format!("{delay}ms")
                    => self.ns
                )
                .run()?;
            }
        }

        Ok(())
    }

    fn delete(&self) -> Result<()> {
        ns_cmd!(
            "sudo",
            "ip",
            "link",
            "delete",
            &self.name
            => self.ns
        )
        .stderr_capture()
        .unchecked()
        .run()?;

        Ok(())
    }
}

struct Bridge {
    name: String,
    addr: Option<(Ipv4Addr, u8)>,
}

impl Bridge {
    /// Creates a new bridge in a namespace.
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            addr: None,
        }
    }

    /// Creates the bridge in the host namespace.
    pub fn create(&self) -> Result<()> {
        let output = duct::cmd!("sudo", "ip", "link", "add", &self.name, "type", "bridge")
            .stderr_capture()
            .unchecked()
            .run()?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            // Delete the bridge if it already exists.
            if stderr.contains("File exists") {
                duct::cmd!("sudo", "ip", "link", "delete", &self.name).run()?;

                // Recreate the bridge.
                return self.create();
            }

            return Err(anyhow::anyhow!(
                "Failed to create bridge {}: {}",
                self.name,
                stderr
            ));
        }

        if let Some((addr, prefix_length)) = &self.addr {
            duct::cmd!(
                "sudo",
                "ip",
                "addr",
                "add",
                format!("{}/{}", addr, prefix_length),
                "dev",
                &self.name
            )
            .run()?;
        }

        Ok(())
    }

    /// Deletes the bridge.
    pub fn delete(&self) -> Result<()> {
        duct::cmd!("sudo", "ip", "link", "delete", &self.name)
            .stderr_capture()
            .unchecked()
            .run()?;

        Ok(())
    }

    /// Adds an interface to the bridge.
    pub fn add_interface(&self, interface: &Veth) -> Result<()> {
        duct::cmd!(
            "sudo",
            "ip",
            "link",
            "set",
            &interface.name,
            "master",
            &self.name
        )
        .run()?;

        Ok(())
    }

    /// Sets the address of the bridge.
    pub fn set_addr(&mut self, addr: Ipv4Addr, prefix_length: u8) {
        self.addr = Some((addr, prefix_length));
    }

    /// Brings the bridge up.
    pub fn up(&self) -> Result<()> {
        duct::cmd!("sudo", "ip", "link", "set", &self.name, "up").run()?;

        Ok(())
    }
}

fn ip_route(ns: &Namespace, dest: impl ToString, dev: &str) -> Result<()> {
    duct::cmd!(
        "sudo",
        "ip",
        "netns",
        "exec",
        ns.name(),
        "ip",
        "route",
        "add",
        dest.to_string(),
        "dev",
        dev
    )
    .run()?;

    Ok(())
}

fn ip_forward(
    ns: &Namespace,
    remote: (impl ToString, u16),
    local: (impl ToString, u16),
) -> Result<()> {
    duct::cmd!(
        "sudo",
        "ip",
        "netns",
        "exec",
        ns.name(),
        "sysctl",
        "-w",
        "net.ipv4.conf.all.route_localnet=1"
    )
    .run()?;

    duct::cmd!(
        "sudo",
        "ip",
        "netns",
        "exec",
        ns.name(),
        "iptables",
        "-t",
        "nat",
        "-A",
        "PREROUTING",
        "-p",
        "tcp",
        "-d",
        remote.0.to_string(),
        "--dport",
        remote.1.to_string(),
        "-j",
        "DNAT",
        "--to-destination",
        format!("{}:{}", local.0.to_string(), local.1)
    )
    .run()?;

    Ok(())
}
