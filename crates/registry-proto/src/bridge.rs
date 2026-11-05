//! What bridges, probes and hubs say to the registry, as JSON, and the
//! list of bridges the registry signs for the clients.
//!
//! ```text
//! POST /vlink/v1/register        Registration → Registered     a bridge reports in
//! GET  /vlink/v1/list            → SignedList                  bridges for a client
//! GET  /vlink/v1/hub/bridges     → Bridges                     bridges to dial (hubs)
//! GET  /vlink/v1/probe/targets   → Bridges                     bridges to probe (probes)
//! POST /vlink/v1/probe/report    ProbeReport                   what a probe found
//! ```

use std::net::{IpAddr, SocketAddr};

use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use veydan_node::list::{unhex, Delegation, Error, SignedList};
use veydan_node::sign::Signer;
use veydan_node::{NodeId, NodeRef};

use crate::revoke::Revocations;
use crate::state::State;

/// What is signed is prefixed with what it is, so that a signature made
/// for one thing is never one for another.
pub const REGISTRATION_CONTEXT: &str = "vlink-register/1\n";
pub const LIST_CONTEXT: &str = "vlink-list/1\n";
/// The version of [`BridgeList`].
pub const LIST_VERSION: u32 = 1;

/// What a bridge sends when it reports in. Signed by the bridge's key,
/// the one its id is the hash of: the registry believes an address for an
/// id only from that key, so nobody else can report the bridge at an
/// address of their own and have it struck off as unreachable there.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    pub id: NodeId,
    pub port: u16,
    /// The bridge's public address, when it knows it; otherwise the one
    /// the request came from is taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    /// Hubs with a link to the bridge right now.
    #[serde(default)]
    pub hubs: u32,
    #[serde(default)]
    pub version: String,
    /// When the bridge made the report, unix seconds: one made long ago
    /// is not taken, so a report cannot be kept and sent again later.
    #[serde(default)]
    pub ts: u64,
    /// The bridge's key, 32 bytes as hex; `id` is its hash.
    #[serde(default)]
    pub key: String,
    /// The key's signature under [`Registration::message`], hex.
    #[serde(default)]
    pub sig: String,
}

/// Why a registration is not believed.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Unsigned {
    #[error("the registration is not signed by the key of its id")]
    Key,
    #[error("the signature of the registration does not hold")]
    Signature,
    #[error("the registration's time is not now: check the clock of the node")]
    Clock,
}

impl Registration {
    /// The bytes the bridge's key signs: everything but the signature.
    pub fn message(&self) -> Vec<u8> {
        let ip = self.ip.map(|ip| ip.to_string()).unwrap_or_default();
        format!(
            "{REGISTRATION_CONTEXT}{}\n{ip}\n{}\n{}\n{}\n{}\n{}",
            self.id, self.port, self.hubs, self.version, self.ts, self.key
        )
        .into_bytes()
    }

    /// Is this the word of the bridge `id`, made within `skew` seconds of
    /// `now`? The key has to be the one the id is the hash of, and the
    /// signature its own over every field.
    pub fn verify(&self, now: u64, skew: u64) -> Result<(), Unsigned> {
        let key: [u8; 32] = unhex(&self.key).ok().and_then(|k| k.try_into().ok()).ok_or(Unsigned::Key)?;
        if NodeId::of_ed25519(&key) != self.id {
            return Err(Unsigned::Key);
        }
        UnparsedPublicKey::new(&ED25519, &key)
            .verify(&self.message(), &unhex(&self.sig).map_err(|_| Unsigned::Signature)?)
            .map_err(|_| Unsigned::Signature)?;
        if self.ts.abs_diff(now) > skew {
            return Err(Unsigned::Clock);
        }
        Ok(())
    }
}

/// What it is told back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registered {
    pub state: State,
    /// The address the registry has for the bridge.
    pub addr: SocketAddr,
    /// The hubs revoked, signed under the root (`revoke`). A registry
    /// that never revoked one, or is older than the field, sends none; a
    /// bridge older than the field reads past it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked: Option<Revocations>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Bridges {
    pub bridges: Vec<NodeRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProbeReport {
    pub id: NodeId,
    pub ok: bool,
}

/// The bridges, and until when the list may be used. Times are unix seconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeList {
    pub v: u32,
    pub issued_at: u64,
    pub expires_at: u64,
    pub bridges: Vec<NodeRef>,
}

/// The bytes the list key signs for a list of bridges (its JSON text).
pub fn list_message(list: &str) -> Vec<u8> {
    veydan_node::list::list_message(LIST_CONTEXT, list)
}

/// As the list key: `list` signed under `delegation`.
pub fn sign_list(signer: &Signer, list: &BridgeList, delegation: &Delegation) -> SignedList {
    signer.sign_list_as(LIST_CONTEXT, list, delegation)
}

/// The list of bridges, when every signature holds and nothing ran out at `now`.
pub fn verify_list(signed: &SignedList, root_hex: &str, now: u64) -> Result<BridgeList, Error> {
    let text = signed.verify_text(LIST_CONTEXT, root_hex, now)?;
    let list: BridgeList = serde_json::from_str(text).map_err(|e| Error::Malformed(e.to_string()))?;
    if list.v != LIST_VERSION {
        return Err(Error::Version(list.v));
    }
    if now >= list.expires_at {
        return Err(Error::Expired);
    }
    Ok(list)
}

/// [`verify_list`] by name on the envelope: `signed.verify(root, now)`.
pub trait SignedBridges {
    fn verify(&self, root_hex: &str, now: u64) -> Result<BridgeList, Error>;
}

impl SignedBridges for SignedList {
    fn verify(&self, root_hex: &str, now: u64) -> Result<BridgeList, Error> {
        verify_list(self, root_hex, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign::SignerExt;

    fn key() -> Signer {
        Signer::from_pkcs8(&Signer::generate_pkcs8()).unwrap()
    }

    fn list(expires_at: u64) -> BridgeList {
        let bridge = |addr: &str, seed: &[u8]| NodeRef { addr: addr.parse().unwrap(), id: NodeId::of_key(seed), sni: None };
        BridgeList {
            v: LIST_VERSION,
            issued_at: 100,
            expires_at,
            bridges: vec![bridge("203.0.113.7:443", b"a"), bridge("[2001:db8::7]:8443", b"b")],
        }
    }

    // A list made once with keys that were thrown away, as it travels: the
    // contract with every client that was ever shipped.
    const ROOT: &str = include_str!("../../../golden/list-root.pub");
    const SIGNED: &str = include_str!("../../../golden/list-signed.json");
    /// Between the list's issue and its expiry.
    const NOW: u64 = 1_800_000_000;

    fn signed() -> SignedList {
        serde_json::from_str(SIGNED).unwrap()
    }

    #[test]
    fn the_golden_list_is_accepted() {
        let list = signed().verify(ROOT.trim(), NOW).unwrap();
        assert_eq!(list.v, LIST_VERSION);
        assert_eq!(list.bridges.len(), 2);
        assert_eq!(list.bridges[0].addr.to_string(), "203.0.113.7:443");
    }

    #[test]
    fn what_ran_out_is_refused() {
        let list = signed().verify(ROOT.trim(), NOW).unwrap();
        assert_eq!(signed().verify(ROOT.trim(), list.expires_at), Err(Error::Expired));
        let delegation_end = signed().delegation.expires_at;
        assert!(delegation_end > list.expires_at, "the golden delegation outlives the list");
        assert_eq!(signed().verify(ROOT.trim(), delegation_end), Err(Error::DelegationExpired));
    }

    #[test]
    fn forgeries_are_refused() {
        // Another root.
        let other = "00".repeat(32);
        assert_eq!(signed().verify(&other, NOW), Err(Error::Delegation));
        // A changed list.
        let mut changed = signed();
        changed.list = changed.list.replace("203.0.113.7", "203.0.113.8");
        assert_eq!(changed.verify(ROOT.trim(), NOW), Err(Error::Signature));
        // A delegation stretched in time.
        let mut stretched = signed();
        stretched.delegation.expires_at += 1;
        assert_eq!(stretched.verify(ROOT.trim(), NOW), Err(Error::Delegation));
        // Garbage where a signature should be.
        let mut garbled = signed();
        garbled.sig = "zz".into();
        assert!(matches!(garbled.verify(ROOT.trim(), NOW), Err(Error::Malformed(_))));
    }

    #[test]
    fn a_list_signed_under_the_root_is_accepted() {
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1000);
        let signed = list_key.sign_list(&list(500), &delegation);
        // It survives the trip as JSON.
        let wire = serde_json::to_string(&signed).unwrap();
        let back: SignedList = serde_json::from_str(&wire).unwrap();
        assert_eq!(back.verify(&root.public_hex(), 200).unwrap(), list(500));
        // A list of another kind, however well signed, is not one of bridges.
        let as_other = list_key.sign_list_as("vcall-list/1\n", &list(500), &delegation);
        assert_eq!(as_other.verify(&root.public_hex(), 200), Err(Error::Signature));
    }

    #[test]
    fn keys_nobody_delegated_are_refused() {
        let (root, list_key, stranger) = (key(), key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1000);
        // A key nobody delegated, signing in the name of one that was.
        let fake = stranger.sign_list(&list(500), &delegation);
        assert_eq!(fake.verify(&root.public_hex(), 200), Err(Error::Signature));
        // A key that delegated itself.
        let own = stranger.delegate(&stranger.public_hex(), 1000);
        assert_eq!(stranger.sign_list(&list(500), &own).verify(&root.public_hex(), 200), Err(Error::Delegation));
    }

    #[test]
    fn a_registration_is_taken_from_the_key_of_its_id_only() {
        let (bridge, stranger) = (key(), key());
        let mut registration = Registration {
            id: bridge.node_id(),
            port: 443,
            ip: Some("203.0.113.7".parse().unwrap()),
            hubs: 2,
            version: "0.2.0".into(),
            ts: 1000,
            key: String::new(),
            sig: String::new(),
        };
        // Unsigned: refused.
        assert_eq!(registration.verify(1000, 300), Err(Unsigned::Key));
        bridge.sign_registration(&mut registration);
        assert_eq!(registration.verify(1000, 300), Ok(()));
        // It survives the trip as JSON.
        let back: Registration = serde_json::from_str(&serde_json::to_string(&registration).unwrap()).unwrap();
        assert_eq!(back.verify(1200, 300), Ok(()));
        // The clocks a little apart is fine; a report from long ago is not.
        assert_eq!(registration.verify(700, 300), Ok(()));
        assert_eq!(registration.verify(1301, 300), Err(Unsigned::Clock));
        assert_eq!(registration.verify(699, 300), Err(Unsigned::Clock));

        // Somebody else's key under the bridge's id: the key is not the
        // id's, whatever it signed.
        let mut forged = registration.clone();
        stranger.sign_registration(&mut forged);
        assert_eq!(forged.verify(1000, 300), Err(Unsigned::Key));
        // The bridge's key, but the address changed after it signed.
        let mut moved = registration.clone();
        moved.ip = Some("198.51.100.9".parse().unwrap());
        assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
        let mut moved = registration.clone();
        moved.port = 8443;
        assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
        // Or the time, to make an old one pass.
        let mut replayed = registration.clone();
        replayed.ts = 5000;
        assert_eq!(replayed.verify(5000, 300), Err(Unsigned::Signature));
        // Or the signature itself is not one.
        let mut garbled = registration.clone();
        garbled.sig = "zz".into();
        assert_eq!(garbled.verify(1000, 300), Err(Unsigned::Signature));
        let mut short = registration.clone();
        short.key.truncate(10);
        assert_eq!(short.verify(1000, 300), Err(Unsigned::Key));
    }

    #[test]
    fn an_answer_without_revocations_is_read_as_before() {
        // What every registry before the field sent.
        let old: Registered = serde_json::from_str(r#"{"state":"verified","addr":"203.0.113.7:443"}"#).unwrap();
        assert_eq!(old, Registered { state: State::Verified, addr: "203.0.113.7:443".parse().unwrap(), revoked: None });
        // And a registry with nothing revoked sends the same text.
        assert_eq!(serde_json::to_string(&old).unwrap(), r#"{"state":"verified","addr":"203.0.113.7:443"}"#);
    }

    #[test]
    fn a_bridge_before_the_field_reads_past_it() {
        // The answer as a bridge before the field read it: two fields, and
        // nothing that refuses others.
        #[derive(Deserialize)]
        struct Before {
            state: State,
            addr: SocketAddr,
        }
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 10_000);
        let revoked = list_key.sign_revocations(vec!["ab".repeat(32)], 1_000, &delegation);
        let now = Registered { state: State::Active, addr: "203.0.113.7:443".parse().unwrap(), revoked: Some(revoked) };
        let text = serde_json::to_string(&now).unwrap();
        let before: Before = serde_json::from_str(&text).unwrap();
        assert_eq!((before.state, before.addr), (State::Active, now.addr));
        let back: Registered = serde_json::from_str(&text).unwrap();
        assert_eq!(back, now);
    }

    /// `UPDATE_GOLDEN=1 cargo test -p registry-proto golden` writes the
    /// list the clients' tests check. The keys that sign it are thrown
    /// away, so that nothing in the golden files can sign anything else.
    #[test]
    fn golden_list() {
        if std::env::var("UPDATE_GOLDEN").is_err() {
            return;
        }
        let (root, list_key) = (key(), key());
        let delegation = root.delegate(&list_key.public_hex(), 1_950_000_000);
        let mut golden = list(1_900_000_000);
        golden.issued_at = 1_790_000_000;
        let signed = list_key.sign_list(&golden, &delegation);
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../golden");
        std::fs::write(format!("{dir}/list-root.pub"), format!("{}\n", root.public_hex())).unwrap();
        std::fs::write(format!("{dir}/list-signed.json"), serde_json::to_string_pretty(&signed).unwrap() + "\n").unwrap();
    }
}
