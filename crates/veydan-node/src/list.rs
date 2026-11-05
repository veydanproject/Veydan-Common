//! A signed list as it travels, and the check of its signatures.
//!
//! A list (of bridges, of call nodes) travels through channels nobody
//! trusts: a bridge, a push, a plain URL. So it is signed, in two steps:
//!
//! - the **root** key, kept off every server, signs a *delegation*: "this
//!   key may sign lists until that day";
//! - the delegated **list key**, which lives on the registry, signs lists.
//!
//! A registry that was taken over can hand out wrong nodes until the
//! delegation runs out, and no longer. A wrong node cannot read what it
//! carries; it can only fail to carry it.
//!
//! What a list holds is the business of `registry-proto`; here is the
//! envelope, and the check that the bytes in it are the list key's word
//! under the root's. This file checks; the signing is in `sign`, with the
//! servers.

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

const DELEGATION_CONTEXT: &str = "vlink-list-key/1\n";

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("malformed: {0}")]
    Malformed(String),
    #[error("the delegation is not signed by the root")]
    Delegation,
    #[error("the delegation ran out")]
    DelegationExpired,
    #[error("the list is not signed by the delegated key")]
    Signature,
    #[error("the list ran out")]
    Expired,
    #[error("list version {0} is not supported")]
    Version(u32),
}

/// "The key `key` may sign lists until `expires_at`", signed by the root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// The list key, 32 bytes as hex.
    pub key: String,
    pub expires_at: u64,
    /// The root's signature, hex.
    pub sig: String,
}

/// A list as it travels: the exact text that was signed, the signature,
/// and the delegation of the key that made it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedList {
    /// The list as JSON. Kept as text: what is verified is these very
    /// bytes, not a re-encoding of them.
    pub list: String,
    pub sig: String,
    pub delegation: Delegation,
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(text: &str) -> Result<Vec<u8>, Error> {
    let bad = || Error::Malformed("not hex".into());
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err(bad());
    }
    (0..text.len() / 2).map(|i| u8::from_str_radix(&text[i * 2..i * 2 + 2], 16).map_err(|_| bad())).collect()
}

/// The bytes the root signs to delegate.
pub fn delegation_message(key_hex: &str, expires_at: u64) -> Vec<u8> {
    format!("{DELEGATION_CONTEXT}{key_hex}\n{expires_at}").into_bytes()
}

/// The bytes the list key signs: the list prefixed with what it is
/// (`context`, e.g. `"vlink-list/1\n"`), so that a signature made for one
/// kind of list is never one for another.
pub fn list_message(context: &str, list: &str) -> Vec<u8> {
    format!("{context}{list}").into_bytes()
}

impl Delegation {
    /// Is this the root's word, and still in force at `now`?
    pub fn verify(&self, root_hex: &str, now: u64) -> Result<(), Error> {
        let root = unhex(root_hex)?;
        UnparsedPublicKey::new(&ED25519, &root)
            .verify(&delegation_message(&self.key, self.expires_at), &unhex(&self.sig)?)
            .map_err(|_| Error::Delegation)?;
        if now >= self.expires_at {
            return Err(Error::DelegationExpired);
        }
        Ok(())
    }
}

impl SignedList {
    /// The text of the list, when the delegation is the root's and in
    /// force at `now`, and the list key signed these bytes in `context`.
    /// What the text says, its version and its own expiry are for the
    /// caller, who knows what kind of list it is.
    pub fn verify_text(&self, context: &str, root_hex: &str, now: u64) -> Result<&str, Error> {
        self.delegation.verify(root_hex, now)?;
        let key = unhex(&self.delegation.key)?;
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(&list_message(context, &self.list), &unhex(&self.sig)?)
            .map_err(|_| Error::Signature)?;
        Ok(&self.list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_goes_both_ways() {
        assert_eq!(hex(&[0, 171, 255]), "00abff");
        assert_eq!(unhex("00abff").unwrap(), vec![0, 171, 255]);
        assert_eq!(unhex("00ABFF").unwrap(), vec![0, 171, 255]);
        assert!(matches!(unhex("abc"), Err(Error::Malformed(_))));
        assert!(matches!(unhex("zz"), Err(Error::Malformed(_))));
        assert!(matches!(unhex("ё"), Err(Error::Malformed(_))));
    }
}
