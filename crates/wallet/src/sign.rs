//! Domain-separated message signing (approved M10 scheme).
//!
//! ```text
//! message_hash(label, payload) = hash_many(&[ b"ox-sigv1", label, payload ])
//! ```
//! `crypto::hash_many` is a length-prefixed SHA3-512, so the two domain labels can never
//! collide with each other or with the transaction-sighash construction (`TxSigningData`
//! bincode-hash, which hashes entirely different bytes). Ed25519 signs the 64-byte digest
//! directly, never the raw payload.
//!
//! * `ox_signMessage` → [`DomainLabel::Personal`] over the raw payload bytes (Ethereum
//!   `personal_sign` semantics: not chain-bound).
//! * `ox_signTypedData` → [`DomainLabel::TypedData`] over RFC-8785-style canonical JSON of the
//!   whole request; the `domain.chainId` field is required, so typed-data signatures are
//!   chain-bound.

use crate::keys::Signer;
use crate::WalletError;
use oxydome_crypto::{hash_many, verify, Hash, PublicKey, Sig};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Scheme tag: any domain label is hashed *with* this so the scheme can evolve without silently
/// accepting old signatures under new rules.
pub const SCHEME_TAG: &[u8] = b"ox-sigv1";

/// The signing domain a payload belongs to. The byte label is injected by the API, never by the
/// caller, so a `personal` signature can never verify as `typed-data` (or vice versa).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DomainLabel {
    /// `ox_signMessage`: raw payload bytes, not chain-bound (Ethereum `personal_sign` analog).
    Personal,
    /// `ox_signTypedData`: canonical JSON of a typed-data request, chain-bound via `chainId`.
    TypedData,
}

impl DomainLabel {
    pub fn as_bytes(&self) -> &'static [u8] {
        match self {
            DomainLabel::Personal => b"personal",
            DomainLabel::TypedData => b"typed-data",
        }
    }
}

/// The canonical domain-separated digest for a label + payload.
pub fn message_hash(label: &DomainLabel, payload: &[u8]) -> Hash {
    hash_many(&[SCHEME_TAG, label.as_bytes(), payload])
}

/// A signed message as it travels on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedMessage {
    /// The signer's public key / address.
    pub pk: PublicKey,
    /// The domain the payload was signed under.
    pub label: DomainLabel,
    /// The exact bytes that were signed (for `Personal`: the message; for `TypedData`: the
    /// canonical JSON).
    pub payload: Vec<u8>,
    /// The digest that the signature commits to (`message_hash(label, payload)`).
    pub sha: Hash,
    pub signature: Sig,
}

impl SignedMessage {
    /// Recomputes the digest from `label + payload` and verifies it matches `sha`, then verifies
    /// the Ed25519 signature over `sha`.
    pub fn verify(&self) -> bool {
        if message_hash(&self.label, &self.payload) != self.sha {
            return false;
        }
        verify(&self.pk, &self.sha.0, &self.signature)
    }

    /// Cheap signature-only verification against an arbitrary digest (used by the reverse
    /// confusion tests; normally use [`SignedMessage::verify`]).
    pub fn verify_signature_over(&self, digest: &Hash) -> bool {
        verify(&self.pk, &digest.0, &self.signature)
    }
}

/// Signs `payload` under `label` with `signer`.
pub fn sign_payload(signer: &impl Signer, label: DomainLabel, payload: Vec<u8>) -> SignedMessage {
    let pk = signer.public();
    let sha = message_hash(&label, &payload);
    let signature = signer.sign(&sha.0);
    SignedMessage {
        pk,
        label,
        payload,
        sha,
        signature,
    }
}

/// RFC-8785-style canonical JSON: objects serialize with lexicographically sorted keys and
/// minimal whitespace, so semantically identical requests produce byte-identical digests.
/// Only JSON strings are escaped (via the standard serializer); numbers are emitted in their
/// canonical `serde_json` form, so `1` and `1.0` are *not* conflated (they serialize differently).
pub fn canonical_json(value: &Value) -> Result<Vec<u8>, WalletError> {
    let mut out = String::with_capacity(128);
    write_canonical(value, &mut out);
    Ok(out.into_bytes())
}

fn write_canonical(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).expect("string is always serializable"))
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(key).expect("key is always serializable"));
                out.push(':');
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

/// Structured signing payload (`ox_signTypedData`). The canonical bytes sign the whole object,
/// and `domain.chainId` is mandatory so signatures cannot be replayed across chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypedData {
    pub primary_type: String,
    pub types: serde_json::Map<String, Value>,
    pub domain: serde_json::Map<String, Value>,
    pub message: Value,
}

impl TypedData {
    /// Builds a typed-data request bound to `chain_id`.
    pub fn new(chain_id: u64, message: Value) -> Self {
        let mut domain = serde_json::Map::new();
        domain.insert("chainId".into(), Value::from(chain_id));
        let mut types = serde_json::Map::new();
        types.insert("Message".to_string(), Value::Array(Vec::new()));
        Self {
            primary_type: "Message".into(),
            types,
            domain,
            message,
        }
    }

    /// Enriches the `domain` object (e.g. `name`, `version`, `salt`). The `chainId` field set by
    /// [`TypedData::new`] is preserved unless explicitly overwritten here.
    pub fn with_domain_field(mut self, key: impl Into<String>, value: Value) -> Self {
        self.domain.insert(key.into(), value);
        self
    }

    pub fn chain_id(&self) -> Option<u64> {
        self.domain.get("chainId").and_then(Value::as_u64)
    }

    pub fn to_value(&self) -> Value {
        Value::Object(serde_json::Map::from_iter(vec![
            ("types".into(), Value::Object(self.types.clone())),
            (
                "primaryType".into(),
                Value::String(self.primary_type.clone()),
            ),
            ("domain".into(), Value::Object(self.domain.clone())),
            ("message".into(), self.message.clone()),
        ]))
    }

    /// Canonical bytes that are signed under [`DomainLabel::TypedData`].
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, WalletError> {
        if self.chain_id().is_none() {
            return Err(WalletError::Signing(
                "typed data requires a domain.chainId".into(),
            ));
        }
        canonical_json(&self.to_value())
    }

    /// Signs the canonical bytes under the `TypedData` domain.
    pub fn sign(&self, signer: &impl Signer) -> Result<SignedMessage, WalletError> {
        let payload = self.canonical_bytes()?;
        Ok(sign_payload(signer, DomainLabel::TypedData, payload))
    }
}

/// Convenience that parses a JSON *string* into a typed-data request.
pub fn sign_typed_data_json(
    signer: &impl Signer,
    json: &str,
) -> Result<SignedMessage, WalletError> {
    let value: Value = serde_json::from_str(json)
        .map_err(|e| WalletError::Signing(format!("invalid JSON: {e}")))?;
    sign_typed_data_value(signer, &value)
}

/// Convenience that derives a [`TypedData`] from a general JSON object. The canonical form the
/// request is signed under is the object itself, so callers are in full control of `domain`.
pub fn sign_typed_data_value(
    signer: &impl Signer,
    value: &Value,
) -> Result<SignedMessage, WalletError> {
    let obj = value
        .as_object()
        .ok_or_else(|| WalletError::Signing("typed data must be a JSON object".into()))?;
    let primary_type = obj
        .get("primaryType")
        .and_then(Value::as_str)
        .unwrap_or("Message")
        .to_string();
    let types = obj
        .get("types")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let domain = obj
        .get("domain")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let message = obj.get("message").cloned().unwrap_or(Value::Null);
    TypedData {
        primary_type,
        types,
        domain,
        message,
    }
    .sign(signer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxydome_crypto::KeyPair;
    use serde_json::json;

    fn key(seed: u8) -> KeyPair {
        KeyPair::from_seed(&[seed; 32])
    }

    #[test]
    fn personal_round_trip() {
        let kp = key(1);
        let sm = sign_payload(&kp, DomainLabel::Personal, b"hello world".to_vec());
        assert!(sm.verify());
    }

    #[test]
    fn tampered_payload_fails() {
        let kp = key(1);
        let mut sm = sign_payload(&kp, DomainLabel::Personal, b"hello world".to_vec());
        sm.payload = b"hello worlD".to_vec();
        assert!(!sm.verify());
    }

    #[test]
    fn wrong_key_fails() {
        let kp = key(1);
        let other = key(2);
        let sm = sign_payload(&kp, DomainLabel::Personal, b"msg".to_vec());
        let mut forged = sm.clone();
        forged.pk = other.public();
        assert!(!forged.verify());
    }

    #[test]
    fn labels_are_disjoint() {
        let kp = key(3);
        let payload = b"sign me".to_vec();
        let personal = sign_payload(&kp, DomainLabel::Personal, payload.clone());
        let typed = sign_payload(&kp, DomainLabel::TypedData, payload);
        assert_ne!(personal.sha, typed.sha);
        assert!(!verify(&kp.public(), &personal.sha.0, &typed.signature));
        assert!(!verify(&kp.public(), &typed.sha.0, &personal.signature));
    }

    #[test]
    fn message_sig_cannot_be_replayed_as_tx_sig() {
        use oxydome_core::{OutPoint, Transaction, TxOutput};
        let kp = key(4);
        // A real signed message.
        let sm = sign_payload(&kp, DomainLabel::Personal, b"approve".to_vec());
        // A real transaction from the same key.
        let mut tx = Transaction::new_unsigned(
            vec![
                (OutPoint::new(Hash::zero(), 0), kp.public()),
                (OutPoint::new(Hash::zero(), 1), kp.public()),
            ],
            vec![TxOutput::spendable(100, kp.public())],
            1,
        );
        tx.sign_owned_inputs(&kp);
        // The message signature must not verify against any tx signing hash...
        for i in 0..tx.inputs.len() {
            let tx_hash = tx.signing_hash(i);
            assert!(
                !sm.verify_signature_over(&tx_hash),
                "message sig accepted as tx input {i}"
            );
        }
        // ...and the tx input signature must not verify as a message.
        for i in 0..tx.inputs.len() {
            let sig = tx.inputs[i].signature;
            let digest = message_hash(&DomainLabel::Personal, b"approve");
            assert!(
                !verify(&kp.public(), &digest.0, &sig),
                "tx sig accepted as message sig"
            );
        }
        assert!(tx.validate_structure().is_ok());
    }

    #[test]
    fn personal_is_deterministic() {
        let kp = key(5);
        let a = sign_payload(&kp, DomainLabel::Personal, b"deterministic".to_vec());
        let b = sign_payload(&kp, DomainLabel::Personal, b"deterministic".to_vec());
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_json_sorts_keys() {
        let a =
            canonical_json(&json!({"b": 1, "a": [3, {"z": null, "y": "s"}], "n": 2.5})).unwrap();
        let b =
            canonical_json(&json!({"n": 2.5, "a": [3, {"y": "s", "z": null}], "b": 1})).unwrap();
        assert_eq!(a, b);
        let text = String::from_utf8(a).unwrap();
        assert_eq!(text, r#"{"a":[3,{"y":"s","z":null}],"b":1,"n":2.5}"#);
    }

    #[test]
    fn typed_data_signs_canonical_bytes() {
        let kp = key(6);
        let td = TypedData::new(42, json!({"to": "0xabc", "amount": 1234}));
        let sm = td.sign(&kp).unwrap();
        assert_eq!(sm.label, DomainLabel::TypedData);
        assert!(sm.verify());
    }

    #[test]
    fn typed_data_requires_chain_id() {
        let kp = key(7);
        let mut td = TypedData::new(1, json!({"x": 1}));
        td.domain.remove("chainId");
        assert!(td.sign(&kp).is_err());
    }

    #[test]
    fn typed_data_is_chain_bound() {
        let kp = key(8);
        let msg = json!({"amount": 100});
        let on_main = TypedData::new(1, msg.clone()).sign(&kp).unwrap();
        let on_test = TypedData::new(42, msg).sign(&kp).unwrap();
        assert_ne!(on_main.sha, on_test.sha);
        assert!(!verify(&kp.public(), &on_main.sha.0, &on_test.signature));
    }

    #[test]
    fn typed_data_accepts_domain_fields() {
        let kp = key(9);
        let td = TypedData::new(1, json!({"n": 1}))
            .with_domain_field("name", Value::String("OxydomeWallet".into()))
            .with_domain_field("version", Value::String("1".into()));
        let sm = td.sign(&kp).unwrap();
        assert!(sm.verify());
        assert!(sm.payload.windows(13).any(|w| w == b"OxydomeWallet"));
    }

    #[test]
    fn golden_vector_personal_sign_seed_5() {
        // Cross-implementation vector: message-signing digest + signature for
        //   pk = Ed25519(seed = [5; 32])
        //   label = personal ("b\"personal\"")
        //   payload = b"Oxydome personal_sign test message"
        // A JS wallet app must reproduce SHA_HEX + SIG_HEX bit-for-bit.
        let kp = KeyPair::from_seed(&[5u8; 32]);
        let sm = sign_payload(
            &kp,
            DomainLabel::Personal,
            b"Oxydome personal_sign test message".to_vec(),
        );
        assert_eq!(
            sm.sha.to_hex(),
            "67e7176e6e8b726005cc806264caee53bf8797c32013a5414975a83e86204cba778a5a0e2f4f6fcf6b616eb4dfc23396cc613b8b55019af451d1a8de97715063"
        );
        assert_eq!(
            sm.signature.to_hex(),
            "fd72c56f00a6bb84c8a7d0f8e07c6958c77cac59c311c2fd9afd81c43db1a3426a2f19170318e7ac26e9e6aacc99eb7e9383f7a1391fe5be5fe3050ab363d704"
        );
        assert!(sm.verify());
        // Hex form of the signature uses the same bytes as to_hex().
        assert_eq!(sm.signature.to_hex(), hex::encode(sm.signature.as_bytes()));
    }
}
