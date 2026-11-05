//! Signing: the root delegates a list key, the list key signs lists, a
//! node's key signs what the node says. Only the servers and the tools of
//! the root key do this; a client only checks (`list`).
//!
//! What is signed — a registration, a list of bridges or of call nodes,
//! the revoked hubs — is the business of `registry-proto`; here is the
//! key and the two things every signer does the same way: a plain
//! signature over bytes, and a list under a delegation.

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Serialize;

use crate::id::NodeId;
use crate::list::{delegation_message, hex, list_message, Delegation, Error, SignedList};

/// A key that signs: the root, a list key or a node's key, from PKCS#8 DER.
pub struct Signer(Ed25519KeyPair);

impl Signer {
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, Error> {
        Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
            .map(Self)
            .map_err(|e| Error::Malformed(format!("not an Ed25519 key: {e}")))
    }

    /// A new key, as PKCS#8 DER: what a node makes on its first start, and
    /// what the tests throw away.
    pub fn generate_pkcs8() -> Vec<u8> {
        let rng = ring::rand::SystemRandom::new();
        Ed25519KeyPair::generate_pkcs8(&rng).expect("the system's randomness").as_ref().to_vec()
    }

    /// The public half, 32 bytes.
    pub fn public_key(&self) -> [u8; 32] {
        let mut public = [0u8; 32];
        public.copy_from_slice(self.0.public_key().as_ref());
        public
    }

    /// The public half, 32 bytes as hex.
    pub fn public_hex(&self) -> String {
        hex(self.0.public_key().as_ref())
    }

    /// The id of the node whose key this is.
    pub fn node_id(&self) -> NodeId {
        NodeId::of_ed25519(&self.public_key())
    }

    /// A signature over `message`, hex.
    pub fn sign(&self, message: &[u8]) -> String {
        hex(self.0.sign(message).as_ref())
    }

    /// As the root: lets `list_key_hex` sign lists until `expires_at`.
    pub fn delegate(&self, list_key_hex: &str, expires_at: u64) -> Delegation {
        let sig = self.0.sign(&delegation_message(list_key_hex, expires_at));
        Delegation { key: list_key_hex.to_string(), expires_at, sig: hex(sig.as_ref()) }
    }

    /// As the list key: signs `list` as JSON under `delegation`, in the
    /// `context` that names what kind of list it is (`"vlink-list/1\n"`,
    /// `"vcall-list/1\n"`): a signature made for one kind is never one for
    /// another.
    pub fn sign_list_as<T: Serialize>(&self, context: &str, list: &T, delegation: &Delegation) -> SignedList {
        let text = serde_json::to_string(list).expect("a list is plain data");
        let sig = self.0.sign(&list_message(context, &text));
        SignedList { list: text, sig: hex(sig.as_ref()), delegation: delegation.clone() }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    fn key() -> Signer {
        Signer::from_pkcs8(&Signer::generate_pkcs8()).unwrap()
    }

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Words(Vec<String>);

    #[test]
    fn a_list_signed_under_the_root_is_accepted_in_its_context_only() {
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1000);
        let words = Words(vec!["a".into(), "b".into()]);
        let signed = list_key.sign_list_as("test-list/1\n", &words, &delegation);
        // It survives the trip as JSON.
        let back: SignedList = serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
        let text = back.verify_text("test-list/1\n", &root.public_hex(), 200).unwrap();
        assert_eq!(serde_json::from_str::<Words>(text).unwrap(), words);
        // The same bytes under another name are nobody's word.
        assert_eq!(back.verify_text("other-list/1\n", &root.public_hex(), 200), Err(Error::Signature));
    }

    #[test]
    fn keys_nobody_delegated_are_refused() {
        let (root, list_key, stranger) = (key(), key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1000);
        let words = Words(vec![]);
        // A key nobody delegated, signing in the name of one that was.
        let fake = stranger.sign_list_as("t\n", &words, &delegation);
        assert_eq!(fake.verify_text("t\n", &root.public_hex(), 200), Err(Error::Signature));
        // A key that delegated itself.
        let own = stranger.delegate(&stranger.public_hex(), 1000);
        assert_eq!(stranger.sign_list_as("t\n", &words, &own).verify_text("t\n", &root.public_hex(), 200), Err(Error::Delegation));
        // The delegation ran out.
        assert_eq!(list_key.sign_list_as("t\n", &words, &delegation).verify_text("t\n", &root.public_hex(), 1000), Err(Error::DelegationExpired));
    }

    #[test]
    fn the_id_of_a_key_is_the_id_of_its_certificate_form() {
        let k = key();
        assert_eq!(k.node_id(), NodeId::of_ed25519(&k.public_key()));
        assert_eq!(k.public_hex().len(), 64);
        let sig = k.sign(b"hello");
        assert_eq!(sig.len(), 128);
    }
}
