# Examples of TLSN usage that works with MP-SPDZ

Here, we provide example of notarization that can generate the proof with sha3 commitment of private part in order to use with MP-SPDZ

- [simple](./simple/README.md) shows how to perform a simple notarization for plain html page.

  This example show how we can specify & create "private" part of the received data. It is different from the "redacted" data in original TLSNotary because the "redacted" data is simply censored out from the message, while the "private" data is both censored out, while still having its corresponding sha3 commitment in the proof to be used later for example with MP-SPDZ.

- [binance](./binance/README.md) shows how to perform notarization of free ETH balance in Binance SPOT account.
  This example represents a slightly more granular control of received data. It does not only have "private" data, but also "redacted" data in the message when verifying as well. We also show in this example how we can specify regex to censor some argument in sent message too!
