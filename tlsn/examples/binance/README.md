## Binance Example: Notarize Private Ethereum Balance from spot account from api.binance.com (Rust)

This example demonstrates using TLSNotary with Binance API.

1. Notarize: Fetch <https://api.binance.com/api/v3/account?/> followed by time, signature, and omitZeroBalances=true to query all non-zero balance of this user. Then we create a proof of the amount of free ETH token in spot account. Most parts of the proof are redacted, while the amount of free ETH in spot account up to 2 decimal points is redacted and included in the proof for further mpspdz usage.

2. Verify the proof.

### 1. Notarize <https://api.binance.com/api/v3/account?> with the queries

Run a simple prover:

```shell
cargo run --release --example binance_prover <notary_host> <notary_port> <api_key> <api_secret> <file_dest> <secret_file_dest>
```

where
<notary_host> <notary_port> can be easily used as prod-notary.mpcstats.org 8003 since we already deployed remote notary to use with MPCStats
<api_key> <api_secret> can be optained from your Binance account by following this [guide](https://github.com/ZKStats/mpc-demo-infra/blob/main/mpc_demo_infra/client_cli/docker/README.md#step-1-get-your-binance-api-key).
<file_dest> specifies the file destination (in json) to store the proof
<secret_file_dest> specifies the file destination to store private data like free ETH balance & its corresponding Nonce needed for proving the secret value in MP-SPDZ later on.

Note that we only create a proof for ETH balance up to 2 decimal points.

If the notarization was successful, you should see this output in the console:

```log
Starting an MPC TLS connection with the server
Got a response from the server
Notarization completed successfully!
```

### 2. Verify the Proof

When you open `proof.json` in an editor, you will see a JSON file with lots of non-human-readable byte arrays. You can decode this file by running:

```shell
cargo run --release --example binance_verifier <proof_file>
```

where <proof_file> specifies the proof file destination to be read from.

We can see the output like this
...

```log
Successfully verified that the bytes below came from a session with Dns("api.binance.com") at 2024-11-03 12:30:50 UTC.
Note that the bytes which the Prover chose not to disclose are shown as X.

Bytes sent:

GET /api/v3/account?timestamp=1730637036395&omitZeroBalances=true&signature=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX HTTP/1.1
host: api.binance.com
x-mbx-apikey: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
accept: */*
accept-encoding: identity
connection: close
user-agent: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


Bytes received:

HTTP/1.1 200 OKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX{"asset":"ETH","free":"YYYYXXXXXX"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
...
```

We can see that YYYY is the only part whose proof is included in the proof.json (which has the commitment of private data), other parts that are XX... are just redacted like in original implementation

### Customization

This 'binance' folder can serve as a template for people to use for creating TLSN proof from other website sources with additional function of having private data and corresponding commitment to prove to other parties later. Here is how you can customize this template.

#### binance_prover.rs

Here is the main file for creating proof. Since most of them are similar to how you modify original TLSNotary, here we will shed light on the part that allows us to be more granular in distinguishing between redacted data that totally got censored (as in original notary) vs private data that got censored but also having their own commitment to be used for proving later on.

Note, in getting data from API, its best to contain as much/ as specific arguments for API query as possible because we prefer the data sent back from API to be as smallest as possible.

Here are parts to be customized (that is in additional to original TLSNotary)

**In main()**: secret_file format. Specify the json format of the secret and its corresponding nonce to be written into.

**In build_proof_with_redactions()**:

First, we censored sent message to not reveal api_key and signature in this case. (This sensor is the same as original TLSNotary because we dont need to have its corresponding commitment)

Then, we obtain recv_public_ranges from specifying the regex that must be redacted & private.

We obtain recv_private_ranges which is the private part that will be accompanied with commitment, by specifying our preferred regex (In our case, ETH free balance of only 2 decimlals precision)

With this structure, there will be some texts that is not in either recv_public_ranges or recv_private_ranges. Those will be just redacted data that are censored without its correponding commitment (like original TLSNotary)

Note, since we decide which part to censor based on regex, it is very important to make sure that the returned data is formatted as you expect when you write regex or else there may result in unexpected data leaking. In our case, we enforce the check that recv transcript ends with uid because this is the assumption that we used to constrain regex in determining recv_public_ranges

#### binance_verifier.rs

Here, we just encapsulate the logic that distinguishes which part is just redacted, and which part is redacted yet still have its commitment to be proved later on as well. (private)

```
    sent.set_redacted(b'X');
    recv.set_redacted(b'X');
    recv.set_private(b'Y');
```
