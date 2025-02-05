# Examples of TLSN usage that works with MP-SPDZ

Here, we provide example of notarization that can generate the proof with sha3 commitment of private part in order to use with MP-SPDZ

- [simple](./simple/README.md) shows how to perform a simple notarization for plain html page.

  This folder is run with automated notary in background, good for testing the logic itself, but we recommend users to use binance folder below as template for better integration with end-to-end-flow.

- [binance](./binance/README.md) shows how to perform notarization of free ETH balance in Binance SPOT account.
  Since this folder is modified to be compatible with whole MPCStats flow using remote notary server, we recommend people to use this folder as a template for those wanting to create TLSNotary proof that not only just contains redacted data (like in original TLSNotary) but also private data that are accompanied with its commitment to be used to prove its property later.
