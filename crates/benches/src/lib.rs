pub mod config;
pub mod metrics;

use std::{io, process::Command};

use hmac_sha256::{MpcPrf, PrfConfig, Role, Prf};
use mpz_common::executor::test_st_executor;
use mpz_garble::{config::Role as DEAPRole, protocol::deap::DEAPThread, Memory};
use mpz_ot::ideal::ot::ideal_ot;

pub const PROVER_NAMESPACE: &str = "prover-ns";
pub const PROVER_INTERFACE: &str = "prover-veth";
pub const PROVER_SUBNET: &str = "10.10.1.0/24";
pub const VERIFIER_NAMESPACE: &str = "verifier-ns";
pub const VERIFIER_INTERFACE: &str = "verifier-veth";
pub const VERIFIER_SUBNET: &str = "10.10.1.1/24";

pub fn set_up() -> io::Result<()> {
    // Create network namespaces
    create_network_namespace(PROVER_NAMESPACE)?;
    create_network_namespace(VERIFIER_NAMESPACE)?;

    // Create veth pair and attach to namespaces
    create_veth_pair(
        PROVER_NAMESPACE,
        PROVER_INTERFACE,
        VERIFIER_NAMESPACE,
        VERIFIER_INTERFACE,
    )?;

    // Set devices up
    set_device_up(PROVER_NAMESPACE, PROVER_INTERFACE)?;
    set_device_up(VERIFIER_NAMESPACE, VERIFIER_INTERFACE)?;

    // Assign IPs
    assign_ip_to_interface(PROVER_NAMESPACE, PROVER_INTERFACE, PROVER_SUBNET)?;
    assign_ip_to_interface(VERIFIER_NAMESPACE, VERIFIER_INTERFACE, VERIFIER_SUBNET)?;

    // Set default routes
    set_default_route(
        PROVER_NAMESPACE,
        PROVER_INTERFACE,
        PROVER_SUBNET.split('/').next().unwrap(),
    )?;
    set_default_route(
        VERIFIER_NAMESPACE,
        VERIFIER_INTERFACE,
        VERIFIER_SUBNET.split('/').next().unwrap(),
    )?;

    Ok(())
}

pub fn clean_up() {
    // Delete interface pair
    if let Err(e) = Command::new("ip")
        .args([
            "netns",
            "exec",
            PROVER_NAMESPACE,
            "ip",
            "link",
            "delete",
            PROVER_INTERFACE,
        ])
        .status()
    {
        println!("Error deleting interface {}: {}", PROVER_INTERFACE, e);
    }

    // Delete namespaces
    if let Err(e) = Command::new("ip")
        .args(["netns", "del", PROVER_NAMESPACE])
        .status()
    {
        println!("Error deleting namespace {}: {}", PROVER_NAMESPACE, e);
    }

    if let Err(e) = Command::new("ip")
        .args(["netns", "del", VERIFIER_NAMESPACE])
        .status()
    {
        println!("Error deleting namespace {}: {}", VERIFIER_NAMESPACE, e);
    }
}

/// Sets the interface parameters.
///
/// Must be run in the correct namespace.
///
/// # Arguments
///
/// * `egress` - The egress bandwidth in mbps.
/// * `burst` - The burst in mbps.
/// * `delay` - The delay in ms.
pub fn set_interface(interface: &str, egress: usize, burst: usize, delay: usize) -> io::Result<()> {
    // Clear rules
    _ = Command::new("tc")
        .arg("qdisc")
        .arg("del")
        .arg("dev")
        .arg(interface)
        .arg("root")
        .status();

    // Egress
    Command::new("tc")
        .arg("qdisc")
        .arg("add")
        .arg("dev")
        .arg(interface)
        .arg("root")
        .arg("handle")
        .arg("1:")
        .arg("tbf")
        .arg("rate")
        .arg(format!("{}mbit", egress))
        .arg("burst")
        .arg(format!("{}mbit", burst))
        .arg("latency")
        .arg("60s")
        .status()?;

    // Delay
    Command::new("tc")
        .arg("qdisc")
        .arg("add")
        .arg("dev")
        .arg(interface)
        .arg("parent")
        .arg("1:1")
        .arg("handle")
        .arg("10:")
        .arg("netem")
        .arg("delay")
        .arg(format!("{}ms", delay))
        .status()?;

    Ok(())
}

/// Create a network namespace with the given name if it does not already exist.
fn create_network_namespace(name: &str) -> io::Result<()> {
    // Check if namespace already exists
    if Command::new("ip")
        .args(["netns", "list"])
        .output()?
        .stdout
        .windows(name.len())
        .any(|ns| ns == name.as_bytes())
    {
        println!("Namespace {} already exists", name);
        return Ok(());
    } else {
        println!("Creating namespace {}", name);
        Command::new("ip").args(["netns", "add", name]).status()?;
    }

    Ok(())
}

fn create_veth_pair(
    left_namespace: &str,
    left_interface: &str,
    right_namespace: &str,
    right_interface: &str,
) -> io::Result<()> {
    // Check if interfaces are already present in namespaces
    if is_interface_present_in_namespace(left_namespace, left_interface)?
        || is_interface_present_in_namespace(right_namespace, right_interface)?
    {
        println!("Virtual interface already exists.");
        return Ok(());
    }

    // Create veth pair
    Command::new("ip")
        .args([
            "link",
            "add",
            left_interface,
            "type",
            "veth",
            "peer",
            "name",
            right_interface,
        ])
        .status()?;

    println!(
        "Created veth pair {} and {}",
        left_interface, right_interface
    );

    // Attach veth pair to namespaces
    attach_interface_to_namespace(left_namespace, left_interface)?;
    attach_interface_to_namespace(right_namespace, right_interface)?;

    Ok(())
}

fn attach_interface_to_namespace(namespace: &str, interface: &str) -> io::Result<()> {
    Command::new("ip")
        .args(["link", "set", interface, "netns", namespace])
        .status()?;

    println!("Attached {} to namespace {}", interface, namespace);

    Ok(())
}

fn set_default_route(namespace: &str, interface: &str, ip: &str) -> io::Result<()> {
    Command::new("ip")
        .args([
            "netns", "exec", namespace, "ip", "route", "add", "default", "via", ip, "dev",
            interface,
        ])
        .status()?;

    println!(
        "Set default route for namespace {} ip {} to {}",
        namespace, ip, interface
    );

    Ok(())
}

fn is_interface_present_in_namespace(
    namespace: &str,
    interface: &str,
) -> Result<bool, std::io::Error> {
    Ok(Command::new("ip")
        .args([
            "netns", "exec", namespace, "ip", "link", "list", "dev", interface,
        ])
        .output()?
        .stdout
        .windows(interface.len())
        .any(|ns| ns == interface.as_bytes()))
}

fn set_device_up(namespace: &str, interface: &str) -> io::Result<()> {
    Command::new("ip")
        .args([
            "netns", "exec", namespace, "ip", "link", "set", interface, "up",
        ])
        .status()?;

    Ok(())
}

fn assign_ip_to_interface(namespace: &str, interface: &str, ip: &str) -> io::Result<()> {
    Command::new("ip")
        .args([
            "netns", "exec", namespace, "ip", "addr", "add", ip, "dev", interface,
        ])
        .status()?;

    Ok(())
}

pub async fn preprocess_prf_circuits() {
    let pms = [42u8; 32];
    let client_random = [69u8; 32];

    let (leader_ctx_0, follower_ctx_0) = test_st_executor(128);
    let (leader_ctx_1, follower_ctx_1) = test_st_executor(128);

    let (leader_ot_send_0, follower_ot_recv_0) = ideal_ot();
    let (follower_ot_send_0, leader_ot_recv_0) = ideal_ot();
    let (leader_ot_send_1, follower_ot_recv_1) = ideal_ot();
    let (follower_ot_send_1, leader_ot_recv_1) = ideal_ot();

    let leader_thread_0 = DEAPThread::new(
        DEAPRole::Leader,
        [0u8; 32],
        leader_ctx_0,
        leader_ot_send_0,
        leader_ot_recv_0,
    );
    let leader_thread_1 = leader_thread_0
        .new_thread(leader_ctx_1, leader_ot_send_1, leader_ot_recv_1)
        .unwrap();

    let follower_thread_0 = DEAPThread::new(
        DEAPRole::Follower,
        [0u8; 32],
        follower_ctx_0,
        follower_ot_send_0,
        follower_ot_recv_0,
    );
    let follower_thread_1 = follower_thread_0
        .new_thread(follower_ctx_1, follower_ot_send_1, follower_ot_recv_1)
        .unwrap();

    // Set up public PMS for testing.
    let leader_pms = leader_thread_0.new_public_input::<[u8; 32]>("pms").unwrap();
    let follower_pms = follower_thread_0
        .new_public_input::<[u8; 32]>("pms")
        .unwrap();

    leader_thread_0.assign(&leader_pms, pms).unwrap();

    let mut leader = MpcPrf::new(
        PrfConfig::builder().role(Role::Leader).build().unwrap(),
        leader_thread_0,
        leader_thread_1,
    );
    let mut follower = MpcPrf::new(
        PrfConfig::builder().role(Role::Follower).build().unwrap(),
        follower_thread_0,
        follower_thread_1,
    );

    futures::join!(
        async {
            leader.setup(leader_pms).await.unwrap();
            leader.set_client_random(Some(client_random)).await.unwrap();
            leader.preprocess().await.unwrap();
        },
        async {
            follower.setup(follower_pms).await.unwrap();
            follower.set_client_random(None).await.unwrap();
            follower.preprocess().await.unwrap();
        }
);
}
