# Rust-BCH

A library to build Bitcoin Cash (BCH) applications in Rust.

[Documentation](https://docs.rs/bch/)

**Author's Note**: Going forward, I will be focusing my efforts on Bitcoin SV and [rust-sv](https://github.com/brentongunning/rust-sv) for reasons that are best stated by [unwriter](https://medium.com/@_unwriter/the-resolution-of-the-bitcoin-cash-experiment-52b86d8cd187). I will not be actively developing this library, however patches are still welcome.


Features

* P2P protocol messages (construction and serialization)
* Address generation (cashaddr and legacy)
* Transaction signing
* Script evaluation
* Node connections and basic message handling
* Wallet key derivation and mnemonic parsing
* Mainnet and testnet support
* Various Bitcoin primitives

*Not Included*: OP_CHECKDATASIG, CTOR validation

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

# License

rust-bch is licensed under the MIT license.
