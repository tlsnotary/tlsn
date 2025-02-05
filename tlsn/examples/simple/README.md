## Simple Example: Notarize Public Data from plain HTML page (Rust) <a name="rust-simple"></a>

This example demonstrates the simplest possible use case for TLSNotary that's compatible with mp-spdz, meaning that in the proof, we can privatize some part of the HTML page, while still showing the hash of those private parts.

Here, we notarize and generate proof of number of from https://jernkunpittaya.github.io/followers-page/party_[i].html where i can be either 0, 1, or 2.

Note that we put number of followers in party_0 as decimal to generalize to float number in the future (Binance Demo)

1. Notarize: Fetch <https://jernkunpittaya.github.io/followers-page/party_[i].html>, where i is either 0, 1, or 2and create a proof of its content.
2. Verify the proof.

Next, we will redact the content and verify it again:

1. Redact the `USER_AGENT` and number of followers (i.e. number after "followers=")
2. Verify the redacted proof.

### 1. Notarize the website

Run a simple prover:

```shell
cargo run --release --example simple_prover <n> <file_dest>
```

where n is either 0, 1, 2, and file_dest is the destination of proof to be written to (ends with .json)

If the notarization was successful, you should see this output in the console: (this is example from n = 1)

```log
Starting an MPC TLS connection with the server
Got a response from the server
Response body:
<!DOCTYPE html>
<html>
<body>
followers=172
</body>
</html>

Party 1 has 172 followers
Received private ranges: [764..767]
Committing to private ranges
Committing to private range 764..767
Revealing private commitment CommitmentId(4)
Received private ranges: [764..767]
Notarization completed successfully!
The proof has been written toproof_1.json
```

Here, we not only censored number of followers but also commit sha3 hash function of this number as well! (However, it still leaks the number of bytes of the number )

⚠️ In this simple example the `Notary` server is automatically started in the background. Note that this is for demonstration purposes only. In a real work example, the notary should be run by a neutral party or the verifier of the proofs. Consult the [Notary Server Docs](https://docs.tlsnotary.org/developers/notary_server.html) for more details on how to run a notary server.

### 2. Verify the Proof

When you open your <file_dest> in an editor, you will see a JSON file with lots of non-human-readable byte arrays. You can decode this file by running:

```shell
cargo run --release --example simple_verifier <file_dest>
```

This will output the TLS-transaction in clear text:

```log
Successfully verified that the bytes below came from a session with Dns("jernkunpittaya.github.io") at 2025-01-30 06:51:58 UTC.
Note that the bytes which the Prover chose not to disclose are shown as X.

Bytes sent:

GET /followers-page/party_1.html HTTP/1.1
host: jernkunpittaya.github.io
accept: */*
accept-encoding: identity
connection: close
user-agent: XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX


Bytes received:

HTTP/1.1 200 OK
Connection: close
Content-Length: 60
Server: GitHub.com
Content-Type: text/html; charset=utf-8
permissions-policy: interest-cohort=()
Last-Modified: Mon, 21 Oct 2024 00:54:44 GMT
Access-Control-Allow-Origin: *
Strict-Transport-Security: max-age=31556952
ETag: "6715a654-3c"
expires: Thu, 30 Jan 2025 06:56:27 GMT
Cache-Control: max-age=600
x-proxy-cache: MISS
X-GitHub-Request-Id: 6FFE:354A6A:2E03FF:3246CD:679B2038
Accept-Ranges: bytes
Age: 332
Date: Thu, 30 Jan 2025 06:51:59 GMT
Via: 1.1 varnish
X-Served-By: cache-bkk2310030-BKK
X-Cache: HIT
X-Cache-Hits: 0
X-Timer: S1738219920.858287,VS0,VE1
Vary: Accept-Encoding
X-Fastly-Request-ID: 6adc03f3dcfa9a7de26344b2be7d23548a9aa5d9

<!DOCTYPE html>
<html>
<body>
followers=
</body>
</html>
...
```

This shows that the followers number is omitted, but still not replaced by some alphabets to show that this place is omitted. (Already addressed in [binance example](../binance/))
