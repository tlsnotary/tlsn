// Set up network namespaces and veth pairs for benchmarking

use std::process::Command;

use tlsn_benches_tc::{
    PROVER_INTERFACE, PROVER_NAMESPACE, PROVER_SUBNET, VERIFIER_INTERFACE, VERIFIER_NAMESPACE,
    VERIFIER_SUBNET,
};

fn main() -> Result<(), std::io::Error> {
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
        PROVER_SUBNET.split('/').nth(0).unwrap(),
    )?;
    set_default_route(
        VERIFIER_NAMESPACE,
        VERIFIER_INTERFACE,
        VERIFIER_SUBNET.split('/').nth(0).unwrap(),
    )?;

    Ok(())
}

/// Create a network namespace with the given name if it does not already exist.
fn create_network_namespace(name: &str) -> Result<(), std::io::Error> {
    // Check if namespace already exists
    if Command::new("sudo")
        .args(&["ip", "netns", "list"])
        .output()?
        .stdout
        .windows(name.len())
        .any(|ns| ns == name.as_bytes())
    {
        println!("Namespace {} already exists", name);
        return Ok(());
    } else {
        println!("Creating namespace {}", name);
        Command::new("sudo")
            .args(&["ip", "netns", "add", name])
            .status()?;
    }

    Ok(())
}

fn create_veth_pair(
    left_namespace: &str,
    left_interface: &str,
    right_namespace: &str,
    right_interface: &str,
) -> Result<(), std::io::Error> {
    // Check if interfaces are already present in namespaces
    if is_interface_present_in_namespace(left_namespace, left_interface)?
        || is_interface_present_in_namespace(right_namespace, right_interface)?
    {
        println!("Virtual interface already exists.");
        return Ok(());
    }

    // Create veth pair
    Command::new("sudo")
        .args(&[
            "ip",
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

fn attach_interface_to_namespace(namespace: &str, interface: &str) -> Result<(), std::io::Error> {
    Command::new("sudo")
        .args(&["ip", "link", "set", interface, "netns", namespace])
        .status()?;

    println!("Attached {} to namespace {}", interface, namespace);

    Ok(())
}

fn set_default_route(namespace: &str, interface: &str, ip: &str) -> Result<(), std::io::Error> {
    Command::new("sudo")
        .args(&[
            "ip", "netns", "exec", namespace, "ip", "route", "add", "default", "via", ip, "dev",
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
    Ok(Command::new("sudo")
        .args(&[
            "ip", "netns", "exec", namespace, "ip", "link", "list", "dev", interface,
        ])
        .output()?
        .stdout
        .windows(interface.len())
        .any(|ns| ns == interface.as_bytes()))
}

fn set_device_up(namespace: &str, interface: &str) -> Result<(), std::io::Error> {
    Command::new("sudo")
        .args(&[
            "ip", "netns", "exec", namespace, "ip", "link", "set", interface, "up",
        ])
        .status()?;

    Ok(())
}

fn assign_ip_to_interface(
    namespace: &str,
    interface: &str,
    ip: &str,
) -> Result<(), std::io::Error> {
    Command::new("sudo")
        .args(&[
            "ip", "netns", "exec", namespace, "ip", "addr", "add", ip, "dev", interface,
        ])
        .status()?;

    Ok(())
}
