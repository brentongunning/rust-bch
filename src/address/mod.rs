//! Address encoding and decoding
//!
//! # Examples
//!
//! Extract the public key hash and address type from a cashaddr address:
//!
//! ```rust
//! use bch::address::cashaddr_decode;
//! use bch::network::Network;
//!
//! let addr = "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2";
//! let (pubkeyhash, addr_type) = cashaddr_decode(&addr, Network::Mainnet).unwrap();
//! ```
//!
//! Encode a public key hash into a legacy base-58 address:
//!
//! ```rust
//! use bch::address::{legacyaddr_encode, AddressType};
//! use bch::network::Network;
//! use bch::util::hash160;
//!
//! let pubkeyhash = hash160(&[0; 33]);
//! let legacyaddr = legacyaddr_encode(&pubkeyhash, AddressType::P2PKH, Network::Mainnet);
//! ```

mod cashaddr;
mod legacyaddr;

pub use self::cashaddr::{cashaddr_decode, cashaddr_encode};
pub use self::legacyaddr::{legacyaddr_decode, legacyaddr_encode};

/// Address type which is either P2PKH or P2SH
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    /// Pay-to-public-key-hash address
    P2PKH,
    /// Pay-to-script-hash address
    P2SH,
}
