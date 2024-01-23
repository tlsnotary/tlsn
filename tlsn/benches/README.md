# TLSNotary bench utilities

This crate provides utilities for benchmarking protocol performance under various network conditions and usage patterns.

As the protocol is mostly IO bound, it's important to track how it performs in low bandwidth and/or high latency environments. To do this we set up temporary network namespaces and add virtual ethernet interfaces which we can control using the linux `tc` (Traffic Control) utility.

## Setup

To start we must create network namespaces for the prover and verifier, respectively.

```sh
ip netns add prover-ns
ip netns add verifier-ns
```

Then we create a pair of virtual ethernet interfaces and add them to their respective namespaces.

```sh
ip link add prover-veth type veth peer name verifier-veth
ip link set prover-veth netns prover-ns
ip link set verifier-veth netns verifier-ns
```

If successful you should be able to see each interface in its namespace. For example, to see the prover interface:

```sh
ip netns exec prover-ns ip link
```

Then, activate each interface (bring it up).

```sh
ip netns exec prover-ns ip link set prover-veth up
ip netns exec verifier-ns ip link set verifier-veth up
```

Next we'll assign IP addresses to each interface and set default routes:

```sh
ip netns exec prover-ns ip addr add 10.10.1.0/24 dev prover-veth
ip netns exec prover-ns ip route add default via 10.10.1.0 dev prover-veth
ip netns exec verifier-ns ip addr add 10.10.1.1/24 dev verifier-veth
ip netns exec verifier-ns ip route add default via 10.10.1.1 dev verifier-veth
```

Verify that everything worked by pinging between them:

```sh
ip netns exec prover-ns ping 10.10.1.1
```

## Clean up

For future reference, you can clean up this configuration as shown below.

First, delete each the interface pair (this removes both):

```sh
ip netns exec prover-ns ip link delete prover-veth
```

Finally, delete each namespace:

```sh
ip netns del prover-ns
ip netns del verifier-ns
```

## Configuration binaries

Alternatively, instead of doing the above configuration manually, you can build the `setup_network` and `cleanup_network` binaries and execute them instead. Though they haven't been tested and you have to run them as root, so use at your own risk.

## Configuring network

To simulate different network conditions we use the linux utility `tc`. Typically, only the egress performance of an interface is configured. So we will configure the egress of both the prover and verifier to simulate the conditions we want.

### Adding rules

For example, to add both an egress bandwidth limit and delay to the prover we can do this:

```sh
ip netns exec prover-ns tc qdisc add dev prover-veth root handle 1: tbf rate 10mbit burst 1mbit latency 60s
ip netns exec prover-ns tc qdisc add dev prover-veth parent 1:1 handle 10: netem delay 50ms
```

The above command will chain a bandwidth filter with a delay filter. The bandwidth filter will cap prover "upload" at 10Mbps with 1Mbps bursts, and drops packets not sent within 60. The delay filter will cause all packets to wait 50ms before arriving at the verifier's network interface.

To simulate a prover with 10Mbps up and 100Mbps down @100ms latency with the verifier, one would also add the following filters to the verifier interface:

```sh
ip netns exec verifier-ns tc qdisc add dev verifier-veth root handle 1: tbf rate 100mbit burst 1mbit latency 60s
ip netns exec verifier-ns tc qdisc add dev verifier-veth parent 1:1 handle 10: netem delay 50ms
```

### Modifying rules

To modify a rule you have to delete the existing one and re-add a new one.

### Deleting rules

You can delete all rules on a device like so:

```sh
ip netns exec prover-ns tc qdisc del dev prover-veth root
```

## Running benches

In order to run a binary in another network namespace you need to run as root, and this won't place nice with cargo. The simplest way to run the bench is to first compile the binaries and run them directly.

```sh
cargo b --bin prover --release
cargo b --bin verifier --release
```

Run these separately:

```sh
ip netns exec prover-ns ../target/release/prover
ip netns exec verifier-ns ../target/release/verifier
```