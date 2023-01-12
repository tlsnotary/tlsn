# tlsn-mpc-core

This crate contains core components for performing MPC, or more specifically 2PC.

## Building

If you're on a Mac:

* `brew install gmp`
* If you're on an M1 Mac, make sure to add `/opt/homebrew/lib` to your `LIBRARY_PATH` environment variable.

## Usage

### Garbled Circuits

todo!

### Oblivious Transfer

todo!

## References

### Garbled Circuits

This crate implements so-called "Half Gate" boolean garbled circuits as described [here](https://eprint.iacr.org/2014/756.pdf).

### Oblivious Transfer

This crate implements Oblivious Transfer Extension using ideas from:
 - [CO15](https://eprint.iacr.org/2015/267.pdf)
 - [IKNP03](https://www.iacr.org/archive/crypto2003/27290145/27290145.pdf)
 - [ALSZ13](https://eprint.iacr.org/2013/552.pdf)
 - [KOS15](https://eprint.iacr.org/2015/546.pdf)

### Existing Works

These projects were referred to heavily during the initial development of this crate:
 - [TLSNotary](https://github.com/tlsnotary/)
 - [Swanky](https://github.com/GaloisInc/swanky)
 - [EMPToolkit](https://github.com/emp-toolkit)
