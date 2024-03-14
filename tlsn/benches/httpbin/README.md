# Httpbin bench for TLSNotary

This bench uses [httpbin](https://httpbin.org) to give some high level
performance numbers for TLSNotary. It works under real network conditions by
using the nightly deployment of the PSE Notary server and the
https://httpbin.org/bytes/{size} endpoint.

# How to use
You can use the default configuration just using `cargo run --release`. It is
also possible to enable `deferred decryption` or using different response
payload `sizes`.

```bash
# Enable deferred decryption and configure response sizes of 128 bytes and 4kb.
cargo run --release -- --defer --size 128,4096
```
