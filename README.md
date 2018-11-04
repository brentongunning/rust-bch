# Rust-BCH

A fresh library to build Bitcoin Cash applications in Rust.

[Documentation](https://docs.rs/bch/)

Features

* P2P protocol messages (construction and serialization)
* Address generation (cashaddr and legacy)
* Transaction signing
* Script evaluation
* Node connections and basic message handling
* Wallet key derivation and mnemonic parsing
* Mainnet and testnet support
* Various Bitcoin primitives

# Installation

Add ```bch = "0.1.0"``` to Cargo.toml

# Requirements

Rust nightly is required for documentation due to a bug fix which has not yet made it to stable.

Run ./configure once to setup nightly.

# Known limitations

This library should not be used for consensus code because its validation checks are incomplete.

# Comparison with other Rust libraries

*rust-bitcoin* - rust-bch has no ties to rust-bitcoin. This library can do everything rust-bitcoin can do and more for Bitcoin Cash.

*parity-bitcoin* - The parity Bitcoin client is a full node in Rust. Its code is more full-featured and also more complex.

*bitcrust* - The bitcrust project is strong in some areas and lacking in others. The two projects could be used together.

# Support for the November 2018 hard fork

This library supports the SV implementation of Bitcoin Cash. It includes the new opcodes OP_MUL, OP_RSHIFT, OP_LSHIFT, and OP_INVERT and the increased script op limit. CDS and CTOR validation are not supported.

# License

rust-bch is licensed under the MIT license.
