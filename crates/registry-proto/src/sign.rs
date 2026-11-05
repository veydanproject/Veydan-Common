//! What the keys of the servers sign, over [`Signer`]: a bridge and a call
//! node their registrations, the list key the lists and the revocations.

use veydan_node::list::{Delegation, SignedList};
pub use veydan_node::sign::Signer;

use crate::bridge::{self, BridgeList, Registration};
use crate::call::{self, CallList};
use crate::revoke::{self, Revocations};

/// The signatures of the registry's forms. In scope, a [`Signer`] signs
/// them by name: `signer.sign_registration(&mut r)`.
pub trait SignerExt {
    /// As a bridge: puts the key and its signature into `registration`,
    /// whose other fields are already filled. The registry takes the
    /// address from a registration only when the key of its id signed
    /// it, so nobody else can move the bridge's id to another address.
    fn sign_registration(&self, registration: &mut Registration);
    /// As the list key: signs the list of bridges under `delegation`.
    fn sign_list(&self, list: &BridgeList, delegation: &Delegation) -> SignedList;
    /// As a call node: the same for its registration (`call`).
    fn sign_call_registration(&self, registration: &mut call::Registration);
    /// As the list key: signs the list of call nodes under `delegation`.
    fn sign_call_list(&self, list: &CallList, delegation: &Delegation) -> SignedList;
    /// As the list key: the hubs of `keys` (SHA-256 of their
    /// SubjectPublicKeyInfo, hex) revoked as of `issued_at`, under
    /// `delegation`.
    fn sign_revocations(&self, keys: Vec<String>, issued_at: u64, delegation: &Delegation) -> Revocations;
}

impl SignerExt for Signer {
    fn sign_registration(&self, registration: &mut Registration) {
        registration.key = self.public_hex();
        registration.sig = self.sign(&registration.message());
    }

    fn sign_list(&self, list: &BridgeList, delegation: &Delegation) -> SignedList {
        self.sign_list_as(bridge::LIST_CONTEXT, list, delegation)
    }

    fn sign_call_registration(&self, registration: &mut call::Registration) {
        registration.key = self.public_hex();
        registration.sig = self.sign(&registration.message());
    }

    fn sign_call_list(&self, list: &CallList, delegation: &Delegation) -> SignedList {
        call::sign_list(self, list, delegation)
    }

    fn sign_revocations(&self, keys: Vec<String>, issued_at: u64, delegation: &Delegation) -> Revocations {
        let mut list = Revocations {
            v: revoke::VERSION,
            keys: revoke::normalize(keys),
            issued_at,
            sig: String::new(),
            delegation: delegation.clone(),
        };
        list.sig = self.sign(&list.message());
        list
    }
}
