//! Authenticated encrypted links for peer and administrator traffic.
//!
//! The wire transport remains deliberately generic; this adapter makes the security
//! policy explicit at the node boundary and is usable for peer↔peer, peer↔admin, and
//! admin↔peer links.

use oxydome_crypto::evk::{EvkError, NodeRole, SecureNodeChannel, SecureNodeEnvelope};
use oxydome_crypto::{KeyPair, PublicKey};

pub struct PeerAdminSecureLink {
    channel: SecureNodeChannel,
    peer: PublicKey,
    peer_role: NodeRole,
}

impl PeerAdminSecureLink {
    pub fn from_authenticated(
        local: &KeyPair,
        local_role: NodeRole,
        exchange: &oxydome_crypto::x25519::X25519StaticKeyPair,
        peer_exchange: &[u8; 32],
        peer: PublicKey,
        peer_role: NodeRole,
        context: &[u8],
        peer_signature: &oxydome_crypto::Sig,
    ) -> Result<Self, EvkError> {
        Ok(Self {
            channel: SecureNodeChannel::establish_authenticated(
                local,
                local_role,
                exchange,
                peer_exchange,
                &peer,
                peer_role,
                context,
                peer_signature,
            )?,
            peer,
            peer_role,
        })
    }

    pub fn encrypt(&mut self, payload: &[u8]) -> Result<SecureNodeEnvelope, EvkError> {
        self.channel.encrypt(payload)
    }

    pub fn decrypt(&mut self, envelope: &SecureNodeEnvelope) -> Result<Vec<u8>, EvkError> {
        if envelope.sender != self.peer || envelope.role != self.peer_role {
            return Err(EvkError::Authentication);
        }
        self.channel.decrypt(envelope)
    }

    pub fn peer(&self) -> PublicKey {
        self.peer
    }
    pub fn peer_role(&self) -> NodeRole {
        self.peer_role
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn peer_admin_and_admin_peer_links_are_authenticated() {
        let peer = KeyPair::generate();
        let admin = KeyPair::generate();
        let peer_exchange = oxydome_crypto::x25519::X25519StaticKeyPair::generate();
        let admin_exchange = oxydome_crypto::x25519::X25519StaticKeyPair::generate();
        let transcript = SecureNodeChannel::handshake_transcript(
            peer_exchange.public().as_bytes(),
            admin_exchange.public().as_bytes(),
            &peer.public(),
            &admin.public(),
            NodeRole::Peer,
            NodeRole::Administrator,
            b"chain-1",
        );
        let peer_signature = peer.sign(transcript.as_bytes());
        let admin_signature = admin.sign(transcript.as_bytes());
        let mut peer_link = PeerAdminSecureLink::from_authenticated(
            &peer,
            NodeRole::Peer,
            &peer_exchange,
            admin_exchange.public().as_bytes(),
            admin.public(),
            NodeRole::Administrator,
            b"chain-1",
            &admin_signature,
        )
        .unwrap();
        let mut admin_link = PeerAdminSecureLink::from_authenticated(
            &admin,
            NodeRole::Administrator,
            &admin_exchange,
            peer_exchange.public().as_bytes(),
            peer.public(),
            NodeRole::Peer,
            b"chain-1",
            &peer_signature,
        )
        .unwrap();
        let envelope = peer_link.encrypt(b"admission request").unwrap();
        assert_eq!(admin_link.decrypt(&envelope).unwrap(), b"admission request");
        let response = admin_link.encrypt(b"admission response").unwrap();
        assert_eq!(peer_link.decrypt(&response).unwrap(), b"admission response");
        let mut forged = envelope.clone();
        forged.role = NodeRole::Administrator;
        assert_eq!(admin_link.decrypt(&forged), Err(EvkError::Authentication));
    }
}
