// Rust Bitcoin Library
// Written in 2014 by
//   Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Network constants
//!
//! This module provides various constants relating to the Bitcoin network
//! protocol, such as protocol versioning and magic header bytes.
//!
//! The [`Network`][1] type implements the [`Decodable`][2] and
//! [`Encodable`][3] traits and encodes the magic bytes of the given
//! network
//!
//! [1]: enum.Network.html
//! [2]: ../../consensus/encode/trait.Decodable.html
//! [3]: ../../consensus/encode/trait.Encodable.html
//!
//! # Example: encoding a network's magic bytes
//!
//! ```rust
//! use bitcoin::network::constants::Network;
//! use bitcoin::consensus::encode::serialize;
//!
//! let network = Network::Bitcoin;
//! let bytes = serialize(&network.magic());
//!
//! assert_eq!(&bytes[..], &[0xF9, 0xBE, 0xB4, 0xD9]);
//! ```

use std::{fmt, io, ops};

use consensus::encode::{self, Decodable, Encodable};

/// Version of the protocol as appearing in network message headers
pub const PROTOCOL_VERSION: u32 = 70001;

user_enum! {
    /// The cryptocurrency to act on
    #[derive(Copy, PartialEq, Eq, PartialOrd, Ord, Clone, Hash)]
    pub enum Network {
        /// Classic Bitcoin
        Bitcoin <-> "bitcoin",
        /// Bitcoin's testnet
        Testnet <-> "testnet",
        /// Bitcoin's regtest
        Regtest <-> "regtest",
        /// Litecoin's mainnet
        Litecoin <-> "litecoin",
        /// Litecoin's testnet
        LitecoinTest <-> "litecoin_test",
        /// BitcoinCash's mainnet
        BitcoinCash <-> "bitcash",
        /// BitcoinCash's testnet
        BitcoinCashTest <-> "bitcash_test",
        /// Dash network
        Dash <-> "dash"
    }
}

impl Network {
    /// Creates a `Network` from the magic bytes.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::Network;
    ///
    /// assert_eq!(Some(Network::Bitcoin), Network::from_magic(0xD9B4BEF9));
    /// assert_eq!(None, Network::from_magic(0xFFFFFFFF));
    /// ```
    pub fn from_magic(magic: u32) -> Option<Network> {
        // Note: any new entries here must be added to `magic` below
        match magic {
            0xD9B4BEF9 => Some(Network::Bitcoin),
            0x0709110B => Some(Network::Testnet),
            0xDAB5BFFA => Some(Network::Regtest),
            0xDBB6C0FB => Some(Network::Litecoin),
            0xF1C8D2FD => Some(Network::LitecoinTest),
            0xE8F3E1E3 => Some(Network::BitcoinCash),
            0xF4F3E5F4 => Some(Network::BitcoinCashTest),
            0xBD6B0CBF => Some(Network::Dash),
            _ => None,
        }
    }

    /// Returns script hashing salt based on network definitions
    pub fn address_type(&self) -> Option<u8> {
        match *self {
            Network::Bitcoin => Some(0),
            Network::BitcoinCash => Some(0),
            Network::Litecoin => Some(48),
            Network::Dash => Some(76),

            Network::Testnet
            | Network::Regtest
            | Network::LitecoinTest
            | Network::BitcoinCashTest => Some(111),
        }
    }

    /// Makes Network from address type
    pub fn from_address_type(t: u8) -> Option<Network> {
        match t {
            0 => Some(Network::Bitcoin),
            48 => Some(Network::Litecoin),
            76 => Some(Network::Dash),
            111 => Some(Network::Testnet),
            _ => None,
        }
    }

    /// Returns pay to script hash salt based on Network
    pub fn address_type_p2sh(&self) -> Option<u8> {
        match *self {
            Network::Bitcoin => Some(5),
            Network::BitcoinCash => Some(5),
            Network::Litecoin => Some(50),
            Network::Dash => Some(16),

            Network::Testnet | Network::BitcoinCashTest | Network::Regtest => Some(196),
            Network::LitecoinTest => Some(58),
        }
    }

    /// Makes Network from address type (p2sh)
    pub fn from_address_type_p2sh(t: u8) -> Option<Network> {
        match t {
            5 => Some(Network::Bitcoin),
            50 => Some(Network::Litecoin),
            16 => Some(Network::Dash),
            196 => Some(Network::Testnet),
            58 => Some(Network::LitecoinTest),
            _ => None,
        }
    }

    /// Returns WIF encode prefix for selected network
    pub fn wif_prefix(&self) -> Option<u8> {
        match *self {
            Network::Bitcoin => Some(128),
            Network::Testnet
            | Network::BitcoinCashTest
            | Network::LitecoinTest
            | Network::Regtest => Some(239),
            Network::Litecoin => Some(176),

            Network::BitcoinCash => Some(128),
            Network::Dash => Some(204),
        }
    }

    /// Makes Network from WIF encoding prefix
    pub fn from_wif(wif: u8) -> Option<Self> {
        match wif {
            128 => Some(Network::Bitcoin),
            176 => Some(Network::Litecoin),
            204 => Some(Network::Dash),
            239 => Some(Network::Regtest),
            _ => None
        }
    }

    /// Returns BECH32 prefix for selected network
    pub fn bech32_prefix(&self) -> Option<&'static str> {
        match *self {
            Network::Bitcoin => Some("bc"),
            Network::Testnet => Some("tb"),
            Network::LitecoinTest => Some("tltc"),
            Network::Regtest => Some("bcrt"),
            Network::Litecoin => Some("ltc"),
            _ => None,
        }
    }

    fn find_bech32_prefix(bech32: &str) -> &str {
        // Split at the last occurrence of the separator character '1'.
        match bech32.rfind("1") {
            None => bech32,
            Some(sep) => bech32.split_at(sep).0,
        }
    }

    /// Makes Network based on BECH32 prefix
    pub fn from_bech32(bech32: &str) -> Option<Self> {
        match Network::find_bech32_prefix(bech32) {
            "bc" | "BC" => Some(Network::Bitcoin),
            "tb" | "TB" => Some(Network::Testnet),
            "ltc" | "LTC" => Some(Network::LitecoinTest),
            "bcrt" | "BCRT" => Some(Network::Regtest),
            "tltc" | "TLTC" => Some(Network::Litecoin),
            _ => None,
        }
    }

    /// Returns extended private key magic number for selected network
    pub fn xprv_magic(&self) -> Option<[u8; 4]> {
        let network_number: Option<u32> = match *self {
            Network::Bitcoin => Some(76066276),
            Network::Testnet => Some(70615956),
            Network::Regtest => Some(70615956),
            Network::Litecoin => Some(27106558),
            Network::LitecoinTest => Some(70615956),
            Network::BitcoinCash => Some(76066276),
            Network::BitcoinCashTest => Some(70615956),
            Network::Dash => Some(50221816),
            // _ => None,
        };
        network_number.map(|v| v.to_be_bytes())
    }

    /// Makes Network from provided extended private key magic number
    pub fn from_xprv(data: &[u8]) -> Option<Self> {
        let number: u32 = 0
            | (data[0] as u32) << 24
            | (data[1] as u32) << 16
            | (data[2] as u32) << 8
            | (data[3] as u32) << 0;

        match number {
            76066276 => Some(Network::Bitcoin),
            70615956 => Some(Network::Testnet),
            27106558 => Some(Network::Litecoin),
            50221816 => Some(Network::Dash),
            // 70615956 => Some(Network::Regtest),
            // 76066276 => Some(Network::BitcoinCash),
            _ => None,
        }
    }

    /// Returns extended public key magic number for selected network
    pub fn xpub_magic(&self) -> Option<[u8; 4]> {
        let network_number: Option<u32> = match *self {
            Network::Bitcoin => Some(76067358),
            Network::Testnet => Some(70617039),
            Network::Regtest => Some(70617039),
            Network::Litecoin => Some(27108450),
            Network::LitecoinTest => Some(70617039),
            Network::BitcoinCash => Some(76067358),
            Network::BitcoinCashTest => Some(70617039),
            Network::Dash => Some(50221772),
            // _ => None,
        };
        network_number.map(|v| v.to_be_bytes())
    }

    /// Makes Network from provided extended private key magic number
    pub fn from_xpub(data: &[u8]) -> Option<Self> {
        let number: u32 = 0
            | (data[0] as u32) << 24
            | (data[1] as u32) << 16
            | (data[2] as u32) << 8
            | (data[3] as u32) << 0;

        match number {
            76067358 => Some(Network::Bitcoin),
            70617039 => Some(Network::Testnet),
            27108450 => Some(Network::Litecoin),
            50221772 => Some(Network::Dash),
            // 70617039 => Some(Network::Regtest),
            // 70617039 => Some(Network::LitecoinTest),
            // 76067358 => Some(Network::BitcoinCash),
            // 70617039 => Some(Network::BitcoinCashTest),
            _ => None,
        }
    }

    /// Return the network magic bytes, which should be encoded little-endian
    /// at the start of every message
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::network::constants::Network;
    ///
    /// let network = Network::Bitcoin;
    /// assert_eq!(network.magic(), 0xD9B4BEF9);
    /// ```
    pub fn magic(&self) -> u32 {
        // Note: any new entries here must be added to `from_magic` above
        match *self {
            Network::Bitcoin => 0xD9B4BEF9,
            Network::Testnet => 0x0709110B,
            Network::Regtest => 0xDAB5BFFA,
            Network::Litecoin => 0xDBB6C0FB,
            Network::LitecoinTest => 0xF1C8D2FD,
            Network::BitcoinCash => 0xE8F3E1E3,
            Network::BitcoinCashTest => 0xF4F3E5F4,
            Network::Dash => 0xBD6B0CBF
        }
    }
}

/// Flags to indicate which network services a node supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ServiceFlags(u64);

impl ServiceFlags {
    /// NONE means no services supported.
    pub const NONE: ServiceFlags = ServiceFlags(0);

    /// NETWORK means that the node is capable of serving the complete block chain. It is currently
    /// set by all Bitcoin Core non pruned nodes, and is unset by SPV clients or other light
    /// clients.
    pub const NETWORK: ServiceFlags = ServiceFlags(1 << 0);

    /// GETUTXO means the node is capable of responding to the getutxo protocol request.  Bitcoin
    /// Core does not support this but a patch set called Bitcoin XT does.
    /// See BIP 64 for details on how this is implemented.
    pub const GETUTXO: ServiceFlags = ServiceFlags(1 << 1);

    /// BLOOM means the node is capable and willing to handle bloom-filtered connections.  Bitcoin
    /// Core nodes used to support this by default, without advertising this bit, but no longer do
    /// as of protocol version 70011 (= NO_BLOOM_VERSION)
    pub const BLOOM: ServiceFlags = ServiceFlags(1 << 2);

    /// WITNESS indicates that a node can be asked for blocks and transactions including witness
    /// data.
    pub const WITNESS: ServiceFlags = ServiceFlags(1 << 3);
    /// COMPACT_FILTERS means the node will service basic block filter requests.
    /// See BIP157 and BIP158 for details on how this is implemented.
    pub const COMPACT_FILTERS: ServiceFlags = ServiceFlags(1 << 6);

    /// NETWORK_LIMITED means the same as NODE_NETWORK with the limitation of only serving the last
    /// 288 (2 day) blocks.
    /// See BIP159 for details on how this is implemented.
    pub const NETWORK_LIMITED: ServiceFlags = ServiceFlags(1 << 10);

    // NOTE: When adding new flags, remember to update the Display impl accordingly.

    /// Add [ServiceFlags] together.
    ///
    /// Returns itself.
    pub fn add(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 |= other.0;
        *self
    }

    /// Remove [ServiceFlags] from this.
    ///
    /// Returns itself.
    pub fn remove(&mut self, other: ServiceFlags) -> ServiceFlags {
        self.0 ^= other.0;
        *self
    }

    /// Check whether [ServiceFlags] are included in this one.
    pub fn has(&self, flags: ServiceFlags) -> bool {
        (self.0 | flags.0) == self.0
    }

    /// Get the integer representation of this [ServiceFlags].
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl fmt::LowerHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::UpperHex for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::UpperHex::fmt(&self.0, f)
    }
}

impl fmt::Display for ServiceFlags {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if *self == ServiceFlags::NONE {
            return write!(f, "ServiceFlags(NONE)");
        }

        let mut flags = self.clone();
        let mut first = true;
        macro_rules! write_flag {
            ($f:ident) => {
                if flags.has(ServiceFlags::$f) {
                    if !first {
                        write!(f, "|")?;
                    }
                    first = false;
                    write!(f, stringify!($f))?;
                    flags.remove(ServiceFlags::$f);
                }
            };
        }
        write!(f, "ServiceFlags(")?;
        write_flag!(NETWORK);
        write_flag!(GETUTXO);
        write_flag!(BLOOM);
        write_flag!(WITNESS);
        write_flag!(COMPACT_FILTERS);
        write_flag!(NETWORK_LIMITED);
        // If there are unknown flags left, we append them in hex.
        if flags != ServiceFlags::NONE {
            if !first {
                write!(f, "|")?;
            }
            write!(f, "0x{:x}", flags)?;
        }
        write!(f, ")")
    }
}

impl From<u64> for ServiceFlags {
    fn from(f: u64) -> Self {
        ServiceFlags(f)
    }
}

impl Into<u64> for ServiceFlags {
    fn into(self) -> u64 {
        self.0
    }
}

impl ops::BitOr for ServiceFlags {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl ops::BitOrAssign for ServiceFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.add(rhs);
    }
}

impl ops::BitXor for ServiceFlags {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self {
        self.remove(rhs)
    }
}

impl ops::BitXorAssign for ServiceFlags {
    fn bitxor_assign(&mut self, rhs: Self) {
        self.remove(rhs);
    }
}

impl Encodable for ServiceFlags {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        self.0.consensus_encode(&mut s)
    }
}

impl Decodable for ServiceFlags {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(ServiceFlags(Decodable::consensus_decode(&mut d)?))
    }
}

#[cfg(test)]
mod tests {
    use super::{Network, ServiceFlags};
    use consensus::encode::{deserialize, serialize};

    #[test]
    fn serialize_test() {
        assert_eq!(
            serialize(&Network::Bitcoin.magic()),
            &[0xf9, 0xbe, 0xb4, 0xd9]
        );
        assert_eq!(
            serialize(&Network::Testnet.magic()),
            &[0x0b, 0x11, 0x09, 0x07]
        );
        assert_eq!(
            serialize(&Network::Regtest.magic()),
            &[0xfa, 0xbf, 0xb5, 0xda]
        );

        assert_eq!(
            deserialize(&[0xf9, 0xbe, 0xb4, 0xd9]).ok(),
            Some(Network::Bitcoin.magic())
        );
        assert_eq!(
            deserialize(&[0x0b, 0x11, 0x09, 0x07]).ok(),
            Some(Network::Testnet.magic())
        );
        assert_eq!(
            deserialize(&[0xfa, 0xbf, 0xb5, 0xda]).ok(),
            Some(Network::Regtest.magic())
        );
    }

    #[test]
    fn string_test() {
        assert_eq!(Network::Bitcoin.to_string(), "bitcoin");
        assert_eq!(Network::Testnet.to_string(), "testnet");
        assert_eq!(Network::Regtest.to_string(), "regtest");
        assert_eq!(Network::Litecoin.to_string(), "litecoin");
        assert_eq!(Network::LitecoinTest.to_string(), "litecoin_test");
        assert_eq!(Network::BitcoinCash.to_string(), "bitcash");
        assert_eq!(Network::BitcoinCashTest.to_string(), "bitcash_test");
        assert_eq!(Network::Dash.to_string(), "dash");

        assert_eq!("bitcoin".parse::<Network>().unwrap(), Network::Bitcoin);
        assert_eq!("testnet".parse::<Network>().unwrap(), Network::Testnet);
        assert_eq!("regtest".parse::<Network>().unwrap(), Network::Regtest);
        assert_eq!("litecoin".parse::<Network>().unwrap(), Network::Litecoin);
        assert_eq!("litecoin_test".parse::<Network>().unwrap(), Network::LitecoinTest);
        assert_eq!("bitcash".parse::<Network>().unwrap(), Network::BitcoinCash);
        assert_eq!("bitcash_test".parse::<Network>().unwrap(), Network::BitcoinCashTest);
        assert_eq!("dash".parse::<Network>().unwrap(), Network::Dash);

        assert!("fakenet".parse::<Network>().is_err());
    }

    #[test]
    fn service_flags_test() {
        let all = [
            ServiceFlags::NETWORK,
            ServiceFlags::GETUTXO,
            ServiceFlags::BLOOM,
            ServiceFlags::WITNESS,
            ServiceFlags::COMPACT_FILTERS,
            ServiceFlags::NETWORK_LIMITED,
        ];

        let mut flags = ServiceFlags::NONE;
        for f in all.iter() {
            assert!(!flags.has(*f));
        }

        flags |= ServiceFlags::WITNESS;
        assert_eq!(flags, ServiceFlags::WITNESS);

        let mut flags2 = flags | ServiceFlags::GETUTXO;
        for f in all.iter() {
            assert_eq!(
                flags2.has(*f),
                *f == ServiceFlags::WITNESS || *f == ServiceFlags::GETUTXO
            );
        }

        flags2 ^= ServiceFlags::WITNESS;
        assert_eq!(flags2, ServiceFlags::GETUTXO);
        flags2 |= ServiceFlags::COMPACT_FILTERS;
        flags2 ^= ServiceFlags::GETUTXO;
        assert_eq!(flags2, ServiceFlags::COMPACT_FILTERS);

        // Test formatting.
        assert_eq!("ServiceFlags(NONE)", ServiceFlags::NONE.to_string());
        assert_eq!("ServiceFlags(WITNESS)", ServiceFlags::WITNESS.to_string());
        let flag = ServiceFlags::WITNESS | ServiceFlags::BLOOM | ServiceFlags::NETWORK;
        assert_eq!("ServiceFlags(NETWORK|BLOOM|WITNESS)", flag.to_string());
        let flag = ServiceFlags::WITNESS | 0xf0.into();
        assert_eq!(
            "ServiceFlags(WITNESS|COMPACT_FILTERS|0xb0)",
            flag.to_string()
        );
    }
}
