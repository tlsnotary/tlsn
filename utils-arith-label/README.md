# Arithmetic label decoding utilities

This crate defines some helper functions for the generation of arithmetic output labels for garbled circuits. Specifically, this crate will generate output labels, sorted by point-and-permute, such that for a secret global field element `Δ`, `labelibit0 = Δ + labelibit1` for all `i`.
