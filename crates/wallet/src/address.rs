//! `ox1…` bech32m addresses.
//!
//! An Oxydome address is the 32-byte Ed25519 public key rendered as a human-friendly, checksummed
//! bech32m string with the `ox` human-readable part (e.g. `ox1qq…`). The raw 32-hex-byte form is
//! still accepted as an alternate input format so existing configurations keep working.

use crate::WalletError;
use bech32::{decode, encode, FromBase32, ToBase32, Variant};
use oxydome_crypto::PublicKey;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// The bech32 human-readable part for Oxydome addresses.
pub const HRP: &str = "ox";

/// Required bech32 encoding variant. `Bech32m` is the checksum algorithm mandated for new
/// chains; some older ecosystems use plain `Bech32`, so the variant is validated explicitly.
pub const VARIANT: Variant = Variant::Bech32m;

fn public_key_to_bytes(pk: &PublicKey) -> Vec<u8> {
    pk.as_bytes().to_vec()
}

fn bytes_to_public_key(bytes: &[u8]) -> Result<PublicKey, WalletError> {
    PublicKey::from_slice(bytes)
        .ok_or_else(|| WalletError::Address("decoded payload is not a 32-byte public key".into()))
}

/// A checksummed Oxydome address: a wrapper over the Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address(PublicKey);

impl Address {
    pub fn new(pk: PublicKey) -> Self {
        Self(pk)
    }

    /// The underlying public key.
    pub fn public_key(&self) -> PublicKey {
        self.0
    }

    /// `ox1…` bech32m rendering of the address.
    pub fn to_bech32(&self) -> String {
        encode(HRP, public_key_to_bytes(&self.0).to_base32(), VARIANT)
            .expect("bech32m encoding of a 32-byte payload cannot fail")
    }

    /// Raw 64-hex-character rendering of the underlying public key.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Parses an address from either its bech32m (`ox1…`) or raw-hex form.
    pub fn from_str_relaxed(s: &str) -> Result<Self, WalletError> {
        s.parse::<Self>()
    }

    fn from_bech32(s: &str) -> Result<Self, WalletError> {
        let (hrp, data, variant) =
            decode(s).map_err(|e| WalletError::Address(format!("invalid bech32: {e}")))?;
        if hrp.as_str() != HRP {
            return Err(WalletError::Address(format!(
                "unexpected human-readable part {hrp:?}, expected {HRP:?}"
            )));
        }
        if variant != VARIANT {
            return Err(WalletError::Address("not a bech32m address".into()));
        }
        let bytes = Vec::<u8>::from_base32(&data)
            .map_err(|e| WalletError::Address(format!("invalid bech32 payload: {e}")))?;
        Ok(Address(bytes_to_public_key(&bytes)?))
    }

    fn from_hex(s: &str) -> Result<Self, WalletError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| WalletError::Address(format!("invalid hex address: {e}")))?;
        Ok(Address(bytes_to_public_key(&bytes)?))
    }
}

impl From<PublicKey> for Address {
    fn from(pk: PublicKey) -> Self {
        Self::new(pk)
    }
}

impl From<Address> for PublicKey {
    fn from(a: Address) -> Self {
        a.public_key()
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_bech32())
    }
}

impl FromStr for Address {
    type Err = WalletError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(a) = Self::from_bech32(s) {
            return Ok(a);
        }
        Self::from_hex(s)
    }
}

impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_bech32())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_str_relaxed(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::KeyPair;

    fn addr_from_seed(seed: [u8; 32]) -> Address {
        Address::new(KeyPair::from_seed(&seed).public())
    }

    #[test]
    fn round_trip_bech32m() {
        let a = addr_from_seed([7u8; 32]);
        let s = a.to_bech32();
        assert!(s.starts_with("ox1"));
        assert_eq!(s.parse::<Address>().unwrap(), a);
    }

    #[test]
    fn checksum_is_validated() {
        let a = addr_from_seed([7u8; 32]);
        let s = a.to_bech32();
        // Flip one payload character; checksum must reject it.
        let malformed = {
            let mut chars: Vec<char> = s.chars().collect();
            let i = (chars.len() / 2).min(chars.len() - 2);
            chars[i] = if chars[i] == 'q' { 'p' } else { 'q' };
            chars.iter().collect::<String>()
        };
        assert!(malformed.parse::<Address>().is_err(), "{malformed} parsed");
    }

    #[test]
    fn rejects_wrong_hrp_and_variant() {
        let a = addr_from_seed([7u8; 32]);
        let s = a.to_bech32();
        let wrong_hrp = format!("tb{s}", s = &s["ox".len()..]);
        assert!(wrong_hrp.parse::<Address>().is_err());
        // Plain bech32 (Variant::Bech32) with the same payload must be rejected too.
        let plain = encode(HRP, public_key_to_bytes(&a.0).to_base32(), Variant::Bech32).unwrap();
        assert!(plain.parse::<Address>().is_err());
    }

    #[test]
    fn hex_form_round_trips() {
        let a = addr_from_seed([9u8; 32]);
        assert_eq!(a.to_hex().parse::<Address>().unwrap(), a);
        assert_eq!(format!("0x{}", a.to_hex()).parse::<Address>().unwrap(), a);
    }

    #[test]
    fn hex_display_equals_raw_public_key() {
        let pk = KeyPair::from_seed(&[3u8; 32]).public();
        let a = Address::new(pk);
        assert_eq!(a.public_key(), pk);
        assert_eq!(a.to_hex(), pk.to_hex());
    }

    #[test]
    fn two_addresses_eq_on_same_pubkey() {
        let pk = KeyPair::from_seed(&[5u8; 32]).public();
        assert_eq!(Address::new(pk), Address::new(pk));
    }

    #[test]
    fn golden_vector_seed_5() {
        // Cross-implementation vector: any wallet library (Rust, JS, …) must derive this exact
        // `ox1…` bech32m address from the Ed25519 public key with seed bytes [5; 32].
        let pk = KeyPair::from_seed(&[5u8; 32]).public();
        assert_eq!(
            pk.to_hex(),
            "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1"
        );
        let addr = Address::new(pk);
        assert_eq!(
            addr.to_bech32(),
            "ox1deapehffkzmcl5f67nz4nrl07nhj49ckdc72duhyl07vmqzst0csm49rtn"
        );
        assert_eq!(addr.to_bech32().parse::<Address>().unwrap(), addr);
    }
}
