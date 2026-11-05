//! What a call node (VCall) says to the registry, and the list of call
//! nodes the registry signs for the clients and the nodes.
//!
//! ```text
//! POST /vlink/v1/calls/register   Registration → Registered   a node reports in
//! GET  /vlink/v1/calls            → SignedList (a CallList)   a few nodes for a client
//! GET  /vlink/v1/calls/all        → SignedList (a CallList)   every node, for nodes
//! ```
//!
//! Both are signed the way the bridges' are (`bridge`), under contexts of
//! their own, so that a signature made for a bridge is never one for a
//! call node and the other way round:
//!
//! - a registration by the node's key (the Ed25519 key whose hash is its
//!   id), over [`Registration::message`];
//! - a list by the registry's list key, the one the root delegated for the
//!   lists of bridges, over `"vcall-list/1\n" + list`. The envelope is the
//!   bridges' [`SignedList`].
//!
//! A registration comes in two forms: `v` 1, the first nodes' (5.1.7 and
//! before: no `v` on the wire), and `v` 2, which says besides how many
//! rooms and cascade uplinks the node holds, under a context of its own.
//! What a `v` 1 report carries of the second form is not under its
//! signature and is not taken. A node of today sends form 2.
//!
//! A list comes in two versions, and both are read: 1 (the first
//! registries: active nodes, the load in percent) and 2 (degraded nodes
//! too, each with its state and class, the load as a share of 1). The
//! registry writes 2.
//!
//! The one copy for every side: the node (`vcall-proto`), the registry
//! (`vhub`), the client (`messenger-vlink`). The answer to a registration
//! and the states are the bridges' ([`Registered`], [`State`]).

use std::net::{IpAddr, SocketAddr};

use ring::signature::{Ed25519KeyPair, KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};

use veydan_node::list::{hex, unhex, Delegation, Error, SignedList};
use veydan_node::sign::Signer;
use veydan_node::{NodeId, NodeRef};

pub use crate::bridge::{Registered, Unsigned};
pub use crate::state::State;

/// What is signed is prefixed with what it is: a registration of form 1,
/// of form 2, a list of call nodes.
pub const REGISTRATION_CONTEXT_V1: &str = "vcall-register/1\n";
pub const REGISTRATION_CONTEXT_V2: &str = "vcall-register/2\n";
pub const LIST_CONTEXT: &str = "vcall-list/1\n";

/// The newest form of [`Registration`]: what a node sends, and the newest
/// the registry takes.
pub const REGISTRATION_VERSION: u32 = 2;
/// The versions of [`CallList`] read. 1 was a list of active nodes with
/// their load in percent; 2 has degraded ones too, with their state, the
/// class and the load as a share. The registry writes [`LIST_VERSION`].
pub const LIST_VERSION_MIN: u32 = 1;
pub const LIST_VERSION: u32 = 2;
/// What a [`CallList`] lists. A list of bridges has no such field, so a
/// list of one kind is never taken for the other.
pub const KIND: &str = "call";
/// The class of every node of the registry: anybody may run one. A client
/// knows the project's own nodes from the manifest, not from here.
pub const CLASS_VOLUNTEER: &str = "volunteer";

/// The most capabilities a node may name, and how long each may be.
pub const MAX_CAPS: usize = 16;
pub const MAX_CAP_LEN: usize = 32;
pub const MAX_REGION_LEN: usize = 16;
pub const MAX_VERSION_LEN: usize = 32;

/// The registration under the name the registry gives it, beside the
/// bridges' `bridge::Registration`.
pub use self::Registration as CallRegistration;

/// How busy a node is, as it says itself. Never believed for anything but
/// the order of a list: a node that lies about it gets more or fewer
/// callers, and nothing else. A `max_*` of 0 is "no limit said".
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Load {
    /// TURN allocations now, and the node's cap on them.
    #[serde(default)]
    pub allocations: u32,
    #[serde(default)]
    pub max_allocations: u32,
    /// Places in SFU rooms now (proxy places of other nodes' participants
    /// too), and the cap: rooms × places.
    #[serde(default)]
    pub participants: u32,
    #[serde(default)]
    pub max_participants: u32,
    /// Bandwidth in use and the node's ceiling, Mbit/s.
    #[serde(default)]
    pub mbps: u32,
    #[serde(default)]
    pub max_mbps: u32,
    /// Rooms now (satellites of the cascade too), and the cap. Form 2.
    #[serde(default)]
    pub rooms: u32,
    #[serde(default)]
    pub max_rooms: u32,
    /// Cascade uplinks to other nodes' rooms now, and the cap. Form 2.
    #[serde(default)]
    pub uplinks: u32,
    #[serde(default)]
    pub max_uplinks: u32,
}

impl Load {
    /// The fullest of the parts, as a share of its limit (0 to 1, in
    /// hundredths): what a client sees. A part without a limit counts 0.
    pub fn share(&self) -> f64 {
        let parts = [
            (self.allocations, self.max_allocations),
            (self.participants, self.max_participants),
            (self.mbps, self.max_mbps),
            (self.rooms, self.max_rooms),
            (self.uplinks, self.max_uplinks),
        ];
        let hundredths = parts
            .iter()
            .map(|&(now, max)| if max == 0 { 0 } else { (u64::from(now) * 100 / u64::from(max)).min(100) })
            .max()
            .unwrap_or(0);
        hundredths as f64 / 100.0
    }

    /// The same in percent (0–100): what the order of a list goes by.
    pub fn percent(&self) -> u8 {
        (self.share() * 100.0).round() as u8
    }

    /// Only what form 1 signed: the parts of form 2 at 0.
    pub fn first_form(&self) -> Load {
        Load { rooms: 0, max_rooms: 0, uplinks: 0, max_uplinks: 0, ..*self }
    }

    fn line(&self) -> String {
        format!(
            "{},{},{},{},{},{}",
            self.allocations, self.max_allocations, self.participants, self.max_participants, self.mbps, self.max_mbps
        )
    }

    fn line_v2(&self) -> String {
        format!("{},{},{},{}", self.rooms, self.max_rooms, self.uplinks, self.max_uplinks)
    }
}

fn first_form() -> u32 {
    1
}

fn is_first_form(v: &u32) -> bool {
    *v <= 1
}

/// What a call node sends when it reports in, every few minutes. Signed by
/// the node's key: the registry believes an address for an id only from
/// that key, so nobody can report a node at an address of their own and
/// have it struck off as unreachable there. The time is under the
/// signature too, so a report kept and sent again later is refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// The form: 1 (or none on the wire) or 2 ([`REGISTRATION_VERSION`]).
    #[serde(default = "first_form", skip_serializing_if = "is_first_form")]
    pub v: u32,
    pub id: NodeId,
    /// The node's public address, when it knows it (`VCALL_PUBLIC_IP`);
    /// otherwise the one the request came from is taken.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpAddr>,
    /// TLS: control, TURN over TLS (`VCALL_LISTEN`, as the world reaches it).
    pub control_port: u16,
    /// STUN and TURN on UDP and TCP (`VCALL_TURN_LISTEN`).
    pub turn_port: u16,
    /// The SFU (`VCALL_SFU_LISTEN`); 0 when the node has none.
    #[serde(default)]
    pub sfu_port: u16,
    /// A hint for clients: `eu`, `ru`. Lowercase letters, digits and `-`;
    /// empty when the operator said nothing.
    #[serde(default)]
    pub region: String,
    #[serde(default)]
    pub version: String,
    /// As in WELCOME: `stun`, `turn`, `turn-tcp`, `turn-tls`, `sfu`…
    #[serde(default)]
    pub caps: Vec<String>,
    #[serde(default)]
    pub load: Load,
    /// When the node made the report, unix seconds.
    #[serde(default)]
    pub ts: u64,
    /// The node's key, 32 bytes as hex; `id` is its hash.
    #[serde(default)]
    pub key: String,
    /// The key's signature under [`Registration::message`], hex.
    #[serde(default)]
    pub sig: String,
}

/// Why a registration is refused before its signature is looked at: what
/// it says cannot be put on one line each, so it could not be signed
/// without ambiguity.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Malformed {
    #[error("the turn port is 0")]
    TurnPort,
    #[error("the control port is 0")]
    ControlPort,
    #[error("the region is not a short word")]
    Region,
    #[error("the version is too long or has a line break")]
    Version,
    #[error("a capability is not a short word, or there are too many")]
    Caps,
    #[error("the form {0} of a registration is not known")]
    Form(u32),
}

fn word(text: &str, max: usize) -> bool {
    text.len() <= max && text.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

impl Registration {
    /// The bytes the node's key signs: every field but the signature, one
    /// per line, the capabilities joined by commas. Form 2 has a context of
    /// its own and the rooms and uplinks on a line after the load.
    pub fn message(&self) -> Vec<u8> {
        let ip = self.ip.map(|ip| ip.to_string()).unwrap_or_default();
        let (context, more) = if is_first_form(&self.v) {
            (REGISTRATION_CONTEXT_V1, String::new())
        } else {
            (REGISTRATION_CONTEXT_V2, format!("\n{}", self.load.line_v2()))
        };
        format!(
            "{context}{}\n{ip}\n{}\n{}\n{}\n{}\n{}\n{}\n{}{more}\n{}\n{}",
            self.id,
            self.control_port,
            self.turn_port,
            self.sfu_port,
            self.region,
            self.version,
            self.caps.join(","),
            self.load.line(),
            self.ts,
            self.key
        )
        .into_bytes()
    }

    /// The load as far as the signature covers it: of form 1, without the
    /// rooms and uplinks, whatever the JSON said of them.
    pub fn signed_load(&self) -> Load {
        if is_first_form(&self.v) {
            self.load.first_form()
        } else {
            self.load
        }
    }

    /// Is every field of a shape that signs without ambiguity?
    pub fn well_formed(&self) -> Result<(), Malformed> {
        if self.v > REGISTRATION_VERSION {
            return Err(Malformed::Form(self.v));
        }
        if self.control_port == 0 {
            return Err(Malformed::ControlPort);
        }
        if self.turn_port == 0 {
            return Err(Malformed::TurnPort);
        }
        if !word(&self.region, MAX_REGION_LEN) {
            return Err(Malformed::Region);
        }
        if self.version.len() > MAX_VERSION_LEN || self.version.contains(['\n', '\r']) {
            return Err(Malformed::Version);
        }
        if self.caps.len() > MAX_CAPS || self.caps.iter().any(|c| c.is_empty() || !word(c, MAX_CAP_LEN)) {
            return Err(Malformed::Caps);
        }
        Ok(())
    }

    /// As the registry: is this the word of the node `id`, made within
    /// `skew` seconds of `now`? The key has to be the one the id is the
    /// hash of, and the signature its own over every field.
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

    /// As the node, with its key as ring holds it: puts the key and its
    /// signature in, the other fields filled already. With a [`Signer`],
    /// `signer.sign_call_registration(&mut r)` (`sign::SignerExt`).
    pub fn sign(&mut self, key: &Ed25519KeyPair) {
        self.key = hex(key.public_key().as_ref());
        self.sig = hex(key.sign(&self.message()).as_ref());
    }

    /// Where the node's control channel is, as the registry takes it.
    pub fn control_addr(&self, seen_from: IpAddr) -> SocketAddr {
        SocketAddr::new(self.ip.unwrap_or(seen_from), self.control_port)
    }
}

impl Registered {
    /// Reported in, and nothing more yet: the node asks again soon.
    pub fn is_new(&self) -> bool {
        self.state == State::New
    }
}

fn volunteer() -> String {
    CLASS_VOLUNTEER.to_string()
}

fn active() -> State {
    State::Active
}

/// The state of a node as a list carries it. A word this build does not
/// know — a registry newer than the app — is a node kept out of the
/// list, not a list refused: the installed apps must go on reading the
/// lists of every registry that comes after them.
fn state_or_kept_out<'de, D: serde::Deserializer<'de>>(d: D) -> Result<State, D::Error> {
    let word = String::deserialize(d)?;
    Ok(State::deserialize(serde::de::value::StrDeserializer::<D::Error>::new(&word)).unwrap_or(State::Degraded))
}

/// One node of a list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallNode {
    /// `address:control_port#id`: what the client pins.
    #[serde(rename = "ref")]
    pub node: NodeRef,
    pub turn_port: u16,
    /// 0: no SFU.
    #[serde(default)]
    pub sfu_port: u16,
    /// The node's own hint (`VCALL_REGION`): the registry does not place
    /// addresses on a map.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub region: String,
    /// What the node reported, as far as its WELCOME to the registry's
    /// last dial-back said the same: `stun`, `turn`, `sfu`, `cascade`…
    #[serde(default)]
    pub caps: Vec<String>,
    /// [`CLASS_VOLUNTEER`] in a list of the registry; version 1 named none.
    #[serde(default = "volunteer")]
    pub class: String,
    /// `active`, or `degraded`: the last check failed, the one before did
    /// not. Version 1 named none: its nodes were active.
    #[serde(default = "active", deserialize_with = "state_or_kept_out")]
    pub state: State,
    /// How full the node said it was when the list was made: the fullest
    /// part of its load, 0 to 1 in hundredths (version 1: percent).
    #[serde(default)]
    pub load: f64,
}

impl CallNode {
    /// The id of the node, as its reference names it.
    pub fn id(&self) -> NodeId {
        self.node.id
    }

    /// Whether the node has the capability `cap` (`stun`, `sfu`, `cascade`…).
    pub fn has(&self, cap: &str) -> bool {
        self.caps.iter().any(|c| c == cap)
    }

    /// The load in percent, whatever the list's `version` wrote.
    pub fn load_percent(&self, version: u32) -> u8 {
        let share = if version == 1 { self.load / 100.0 } else { self.load };
        (share.clamp(0.0, 1.0) * 100.0).round() as u8
    }
}

/// Call nodes and until when the list may be used. Times are unix seconds.
///
/// The list for a client (`complete: false`) has the least loaded few, in
/// an order of the client's own; the list for nodes (`complete: true`) has
/// every node a client may be given, by id, so that a node can tell whether
/// another one is in the registry at all.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CallList {
    pub v: u32,
    pub kind: String,
    #[serde(default)]
    pub complete: bool,
    pub issued_at: u64,
    pub expires_at: u64,
    pub nodes: Vec<CallNode>,
}

/// The bytes the list key signs for a list of call nodes (its JSON text).
pub fn list_message(list: &str) -> Vec<u8> {
    veydan_node::list::list_message(LIST_CONTEXT, list)
}

/// As the registry: `list` signed by the list key under `delegation`.
pub fn sign_list(signer: &Signer, list: &CallList, delegation: &Delegation) -> SignedList {
    signer.sign_list_as(LIST_CONTEXT, list, delegation)
}

/// As a node or a client: the list, when the root delegated the key that
/// signed it, it is a list of call nodes of a version known, and nothing
/// ran out at `now`.
pub fn verify_list(signed: &SignedList, root_hex: &str, now: u64) -> Result<CallList, Error> {
    let text = signed.verify_text(LIST_CONTEXT, root_hex, now)?;
    let list: CallList = serde_json::from_str(text).map_err(|e| Error::Malformed(e.to_string()))?;
    if !(LIST_VERSION_MIN..=LIST_VERSION).contains(&list.v) {
        return Err(Error::Version(list.v));
    }
    if list.kind != KIND {
        return Err(Error::Malformed(format!("a list of {}, not of call nodes", list.kind)));
    }
    if now >= list.expires_at {
        return Err(Error::Expired);
    }
    Ok(list)
}

/// [`verify_list`] by name on the envelope: `signed.verify_calls(root, now)`.
pub trait SignedCalls {
    fn verify_calls(&self, root_hex: &str, now: u64) -> Result<CallList, Error>;
}

impl SignedCalls for SignedList {
    fn verify_calls(&self, root_hex: &str, now: u64) -> Result<CallList, Error> {
        verify_list(self, root_hex, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::{BridgeList, SignedBridges};
    use crate::sign::SignerExt;

    fn signer() -> Signer {
        Signer::from_pkcs8(&Signer::generate_pkcs8()).unwrap()
    }

    fn pair() -> Ed25519KeyPair {
        Ed25519KeyPair::from_pkcs8(&Signer::generate_pkcs8()).unwrap()
    }

    /// Form 1 as the first nodes sent it, unsigned.
    fn unsigned(id: NodeId) -> Registration {
        Registration {
            v: 1,
            id,
            ip: Some("203.0.113.7".parse().unwrap()),
            control_port: 8443,
            turn_port: 3478,
            sfu_port: 0,
            region: "eu".into(),
            version: "0.1.0".into(),
            caps: vec!["stun".into(), "turn".into()],
            load: Load { allocations: 10, max_allocations: 1000, mbps: 30, max_mbps: 100, ..Load::default() },
            ts: 1000,
            key: String::new(),
            sig: String::new(),
        }
    }

    /// Form 2: the cascade, and the rooms and uplinks.
    fn second(mut r: Registration) -> Registration {
        r.v = REGISTRATION_VERSION;
        r.caps.push("cascade".into());
        r.load.rooms = 3;
        r.load.max_rooms = 64;
        r.load.uplinks = 2;
        r.load.max_uplinks = 256;
        r
    }

    fn id_of(key: &Ed25519KeyPair) -> NodeId {
        NodeId::of_ed25519(key.public_key().as_ref().try_into().unwrap())
    }

    fn registration(key: &Ed25519KeyPair) -> Registration {
        let mut r = unsigned(id_of(key));
        r.sign(key);
        r
    }

    fn second_form(key: &Ed25519KeyPair) -> Registration {
        let mut r = second(unsigned(id_of(key)));
        r.sign(key);
        r
    }

    #[test]
    fn a_registration_is_taken_from_the_key_of_its_id_only() {
        let (node, stranger) = (pair(), pair());
        for r in [registration(&node), second_form(&node)] {
            assert_eq!(r.verify(1000, 300), Ok(()));
            assert_eq!(r.well_formed(), Ok(()));
            assert_eq!(r.control_addr("9.9.9.9".parse().unwrap()), "203.0.113.7:8443".parse().unwrap());
            // It survives the trip as JSON, and a node that leaves out what it
            // has not got (no SFU, no load yet) signs the defaults.
            let back: Registration = serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
            assert_eq!(back.verify(1200, 300), Ok(()));
            assert_eq!(r.verify(1301, 300), Err(Unsigned::Clock));

            let mut forged = r.clone();
            forged.sign(&stranger);
            assert_eq!(forged.verify(1000, 300), Err(Unsigned::Key));
            let mut garbled = r.clone();
            garbled.sig = "zz".into();
            assert_eq!(garbled.verify(1000, 300), Err(Unsigned::Signature));
            // Every field is under the signature: the address, the ports, the
            // load a node is ordered by, the time, the form.
            let changes: [fn(&mut Registration); 10] = [
                |r| r.ip = Some("198.51.100.9".parse().unwrap()),
                |r| r.ip = None,
                |r| r.turn_port = 3479,
                |r| r.sfu_port = 3479,
                |r| r.control_port = 443,
                |r| r.load.allocations = 0,
                |r| r.caps.push("sfu".into()),
                |r| r.region = "ru".into(),
                |r| r.ts += 1,
                |r| r.v = 3 - r.v,
            ];
            for change in changes {
                let mut moved = r.clone();
                change(&mut moved);
                assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
            }
        }
        // Form 2 signs the rooms and uplinks too.
        let r = second_form(&node);
        for change in [|r: &mut Registration| r.load.rooms = 0, |r: &mut Registration| r.load.max_uplinks = 1] {
            let mut moved = r.clone();
            change(&mut moved);
            assert_eq!(moved.verify(1000, 300), Err(Unsigned::Signature));
        }
        assert_eq!(r.signed_load(), r.load);
        // Form 1 does not: what it says of them is not taken.
        let mut first = registration(&node);
        first.load.rooms = 60;
        first.load.max_rooms = 64;
        assert_eq!(first.verify(1000, 300), Ok(()));
        assert_eq!(first.signed_load(), registration(&node).load);
    }

    #[test]
    fn a_signer_signs_as_the_key_does() {
        let der = Signer::generate_pkcs8();
        let (signer, key) = (Signer::from_pkcs8(&der).unwrap(), Ed25519KeyPair::from_pkcs8(&der).unwrap());
        let mut by_signer = second(unsigned(signer.node_id()));
        signer.sign_call_registration(&mut by_signer);
        let mut by_key = by_signer.clone();
        by_key.sign(&key);
        assert_eq!(by_signer, by_key);
        assert_eq!(by_signer.verify(1000, 300), Ok(()));
    }

    #[test]
    fn the_signed_lines_are_the_documented_ones() {
        let node = pair();
        let r = registration(&node);
        let head = format!("{}\n203.0.113.7\n8443\n3478\n0\neu\n0.1.0\n", r.id);
        let first = format!("vcall-register/1\n{head}stun,turn\n10,1000,0,0,30,100\n1000\n{}", r.key);
        assert_eq!(String::from_utf8(r.message()).unwrap(), first);
        // A node of 5.1.7 sends no `v`, and a form-1 report is written so.
        assert!(!serde_json::to_string(&r).unwrap().contains("\"v\""));
        let r = second_form(&node);
        let second = format!("vcall-register/2\n{head}stun,turn,cascade\n10,1000,0,0,30,100\n3,64,2,256\n1000\n{}", r.key);
        assert_eq!(String::from_utf8(r.message()).unwrap(), second);
        assert!(serde_json::to_string(&r).unwrap().starts_with("{\"v\":2,"));
        let mut r = second_form(&node);
        r.v = 3;
        assert_eq!(r.well_formed(), Err(Malformed::Form(3)));
    }

    #[test]
    fn what_cannot_be_signed_plainly_is_refused() {
        let node = pair();
        let mut r = registration(&node);
        r.caps = vec!["stun,turn".into()];
        assert_eq!(r.well_formed(), Err(Malformed::Caps));
        r.caps = vec!["x".into(); MAX_CAPS + 1];
        assert_eq!(r.well_formed(), Err(Malformed::Caps));
        r.caps = vec![String::new()];
        assert_eq!(r.well_formed(), Err(Malformed::Caps));
        let mut r = registration(&node);
        r.region = "eu\nx".into();
        assert_eq!(r.well_formed(), Err(Malformed::Region));
        let mut r = registration(&node);
        r.version = "1\n2".into();
        assert_eq!(r.well_formed(), Err(Malformed::Version));
        let mut r = registration(&node);
        r.turn_port = 0;
        assert_eq!(r.well_formed(), Err(Malformed::TurnPort));
        r.turn_port = 3478;
        r.control_port = 0;
        assert_eq!(r.well_formed(), Err(Malformed::ControlPort));
    }

    #[test]
    fn load_is_the_fullest_part() {
        assert_eq!((Load::default().share(), Load::default().percent()), (0.0, 0));
        let load = Load { allocations: 500, max_allocations: 1000, mbps: 90, max_mbps: 100, ..Load::default() };
        assert_eq!((load.share(), load.percent()), (0.9, 90));
        assert_eq!(Load { allocations: 5000, max_allocations: 1000, ..Load::default() }.share(), 1.0);
        // Rooms and uplinks count as the other parts do.
        assert_eq!(Load { rooms: 48, max_rooms: 64, mbps: 10, max_mbps: 100, ..Load::default() }.share(), 0.75);
        assert_eq!(Load { uplinks: 1, max_uplinks: 3, ..Load::default() }.percent(), 33);
        // A part without a limit is no part.
        assert_eq!(Load { participants: 700, ..Load::default() }.share(), 0.0);
    }

    #[test]
    fn the_answer_is_the_bridges_and_says_when_the_node_is_new() {
        let answer: Registered = serde_json::from_str(r#"{"state":"new","addr":"203.0.113.7:8443"}"#).unwrap();
        assert!(answer.is_new());
        let answer: Registered = serde_json::from_str(r#"{"state":"active","addr":"203.0.113.7:8443"}"#).unwrap();
        assert!(!answer.is_new());
        assert_eq!(answer.state.to_string(), "active");
    }

    fn node_of(id: NodeId, state: State) -> CallNode {
        CallNode {
            node: format!("203.0.113.7:8443#{id}").parse().unwrap(),
            turn_port: 3478,
            sfu_port: 3479,
            region: "eu".into(),
            caps: vec!["stun".into(), "cascade".into()],
            class: CLASS_VOLUNTEER.into(),
            state,
            load: 0.03,
        }
    }

    fn list_of(nodes: Vec<CallNode>) -> CallList {
        CallList { v: LIST_VERSION, kind: KIND.into(), complete: true, issued_at: 100, expires_at: 5000, nodes }
    }

    #[test]
    fn a_list_is_taken_under_the_root_and_never_for_a_bridge_list() {
        let (root, list_key) = (signer(), signer());
        let delegation = root.delegate(&list_key.public_hex(), 10_000);
        let id = NodeId::of_key(b"n");
        let list = list_of(vec![node_of(id, State::Degraded)]);
        let signed = list_key.sign_call_list(&list, &delegation);
        assert_eq!(signed, sign_list(&list_key, &list, &delegation));
        let wire: SignedList = serde_json::from_str(&serde_json::to_string(&signed).unwrap()).unwrap();
        let got = wire.verify_calls(&root.public_hex(), 200).unwrap();
        assert_eq!(got, list);
        assert_eq!(got.nodes[0].id(), id);
        assert!(got.nodes[0].has("cascade") && !got.nodes[0].has("sfu"));
        assert_eq!(got.nodes[0].load_percent(got.v), 3);
        // As the registry writes it.
        let expected = format!(
            "{{\"v\":2,\"kind\":\"call\",\"complete\":true,\"issued_at\":100,\"expires_at\":5000,\"nodes\":[{{\"ref\":\"203.0.113.7:8443#{id}\",\
             \"turn_port\":3478,\"sfu_port\":3479,\"region\":\"eu\",\"caps\":[\"stun\",\"cascade\"],\"class\":\"volunteer\",\
             \"state\":\"degraded\",\"load\":0.03}}]}}"
        );
        assert_eq!(wire.list, expected);
        assert_eq!(verify_list(&wire, &root.public_hex(), 5000), Err(Error::Expired));
        assert_eq!(verify_list(&wire, &"00".repeat(32), 200), Err(Error::Delegation));

        // Signed for bridges, the same key and delegation: no list of nodes.
        let bridges = BridgeList { v: crate::bridge::LIST_VERSION, issued_at: 100, expires_at: 5000, bridges: vec![] };
        let as_bridges = list_key.sign_list(&bridges, &delegation);
        assert_eq!(verify_list(&as_bridges, &root.public_hex(), 200), Err(Error::Signature));
        // And the call list is no list of bridges.
        assert_eq!(signed.verify(&root.public_hex(), 200), Err(Error::Signature));

        let mut changed = signed.clone();
        changed.list = changed.list.replace("3478", "3477");
        assert_eq!(verify_list(&changed, &root.public_hex(), 200), Err(Error::Signature));
        // A list of another kind, a version not known.
        let other = sign_list(&list_key, &CallList { kind: "bridge".into(), ..list.clone() }, &delegation);
        assert!(matches!(verify_list(&other, &root.public_hex(), 200), Err(Error::Malformed(_))));
        let newer = sign_list(&list_key, &CallList { v: LIST_VERSION + 1, ..list.clone() }, &delegation);
        assert_eq!(verify_list(&newer, &root.public_hex(), 200), Err(Error::Version(LIST_VERSION + 1)));
        let older = sign_list(&list_key, &CallList { v: 0, ..list }, &delegation);
        assert_eq!(verify_list(&older, &root.public_hex(), 200), Err(Error::Version(0)));
    }

    #[test]
    fn a_list_of_the_first_version_is_read_as_the_first_registries_wrote_it() {
        let (root, list_key) = (signer(), signer());
        let delegation = root.delegate(&list_key.public_hex(), 10_000);
        let id = NodeId::of_key(b"n");
        // Version 1: no `complete`, class, state or SFU; the load in percent.
        let text = format!(
            r#"{{"v":1,"kind":"call","issued_at":100,"expires_at":5000,"nodes":[{{"ref":"203.0.113.7:8443#{id}","turn_port":3478,"caps":["stun"],"load":30}}]}}"#
        );
        let sig = list_key.sign(&list_message(&text));
        let signed = SignedList { list: text, sig, delegation };
        let read = verify_list(&signed, &root.public_hex(), 200).unwrap();
        let n = &read.nodes[0];
        assert_eq!((read.v, read.complete, n.state, n.class.as_str(), n.sfu_port), (1, false, State::Active, CLASS_VOLUNTEER, 0));
        assert_eq!((n.load, n.load_percent(read.v)), (30.0, 30));
    }

    // Made once with keys that were thrown away, as they travel: the
    // contract with every node, registry and client that was ever shipped.
    const REGISTRATION_V1: &str = include_str!("../../../golden/call-registration-v1.json");
    const REGISTRATION_V2: &str = include_str!("../../../golden/call-registration-v2.json");
    const LIST_ROOT: &str = include_str!("../../../golden/call-list-root.pub");
    const LIST_SIGNED: &str = include_str!("../../../golden/call-list-signed.json");
    /// When the golden registrations were made; between the golden list's
    /// issue and its expiry.
    const NOW: u64 = 1_800_000_000;

    fn golden(text: &str) -> Registration {
        serde_json::from_str(text).unwrap()
    }

    fn golden_list() -> SignedList {
        serde_json::from_str(LIST_SIGNED).unwrap()
    }

    #[test]
    fn the_golden_registrations_are_accepted_as_written() {
        for (text, v) in [(REGISTRATION_V1, 1), (REGISTRATION_V2, 2)] {
            let r = golden(text);
            assert_eq!((r.v, r.verify(NOW, 300), r.well_formed()), (v, Ok(()), Ok(())));
            // The text is the one this crate writes.
            assert_eq!(serde_json::to_string_pretty(&r).unwrap() + "\n", text);
            // Too late, or changed, it is not.
            assert_eq!(r.verify(NOW + 301, 300), Err(Unsigned::Clock));
            let mut moved = r.clone();
            moved.control_port = 443;
            assert_eq!(moved.verify(NOW, 300), Err(Unsigned::Signature));
            let mut other = r.clone();
            other.id = NodeId::of_key(b"another");
            assert_eq!(other.verify(NOW, 300), Err(Unsigned::Key));
        }
        // Form 1 on the wire has no `v`, form 2 has.
        assert!(!REGISTRATION_V1.contains("\"v\""));
        assert!(REGISTRATION_V2.contains("\"v\": 2"));
        let r = golden(REGISTRATION_V2);
        let head = format!("{}\n203.0.113.7\n8443\n3478\n3479\neu\n0.1.4\n", r.id);
        let lines = format!("vcall-register/2\n{head}stun,turn,sfu,cascade\n10,1000,3,768,30,100\n3,64,2,256\n{NOW}\n{}", r.key);
        assert_eq!(String::from_utf8(r.message()).unwrap(), lines);
    }

    #[test]
    fn a_state_this_build_does_not_know_keeps_the_node_out_not_the_list() {
        let node = |state: &str| format!(r#"{{"ref":"203.0.113.7:8443#{}","turn_port":3478,"state":"{state}"}}"#, NodeId::of_key(b"a"));
        let known: CallNode = serde_json::from_str(&node("degraded")).unwrap();
        assert_eq!(known.state, State::Degraded);
        let later: CallNode = serde_json::from_str(&node("quarantined")).unwrap();
        assert_eq!(later.state, State::Degraded, "kept out, as a degraded node is");
        assert_eq!(serde_json::from_str::<CallNode>(&node("")).unwrap().state, State::Degraded);
    }

    #[test]
    fn the_golden_list_is_accepted() {
        let list = golden_list().verify_calls(LIST_ROOT.trim(), NOW).unwrap();
        assert_eq!((list.v, list.kind.as_str(), list.complete), (LIST_VERSION, KIND, false));
        assert_eq!(list.nodes.len(), 2);
        assert_eq!(list.nodes[0].node.to_string(), format!("203.0.113.7:8443#{}", NodeId::of_key(b"a")));
        assert_eq!((list.nodes[0].state, list.nodes[0].load_percent(list.v)), (State::Active, 3));
        assert_eq!((list.nodes[1].state, list.nodes[1].sfu_port, list.nodes[1].region.as_str()), (State::Degraded, 0, ""));
    }

    #[test]
    fn the_golden_list_is_refused_when_ran_out_changed_or_of_another_root() {
        let list = golden_list().verify_calls(LIST_ROOT.trim(), NOW).unwrap();
        assert_eq!(golden_list().verify_calls(LIST_ROOT.trim(), list.expires_at), Err(Error::Expired));
        let delegation_end = golden_list().delegation.expires_at;
        assert!(delegation_end > list.expires_at, "the golden delegation outlives the list");
        assert_eq!(golden_list().verify_calls(LIST_ROOT.trim(), delegation_end), Err(Error::DelegationExpired));
        assert_eq!(golden_list().verify_calls(&"00".repeat(32), NOW), Err(Error::Delegation));
        let mut changed = golden_list();
        changed.list = changed.list.replace("203.0.113.7", "203.0.113.8");
        assert_eq!(changed.verify_calls(LIST_ROOT.trim(), NOW), Err(Error::Signature));
        let mut stretched = golden_list();
        stretched.delegation.expires_at += 1;
        assert_eq!(stretched.verify_calls(LIST_ROOT.trim(), NOW), Err(Error::Delegation));
        // And it is no list of bridges.
        assert_eq!(golden_list().verify(LIST_ROOT.trim(), NOW), Err(Error::Signature));
    }

    /// `UPDATE_GOLDEN=1 cargo test -p registry-proto golden` writes the
    /// registrations and the list the tests of every side check. The keys
    /// that sign them are thrown away, so that nothing in the golden files
    /// can sign anything else.
    #[test]
    fn golden_calls() {
        if std::env::var("UPDATE_GOLDEN").is_err() {
            return;
        }
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../golden");
        let write = |name: &str, text: String| std::fs::write(format!("{dir}/{name}"), text).unwrap();
        fn json<T: Serialize>(value: &T) -> String {
            serde_json::to_string_pretty(value).unwrap() + "\n"
        }

        let node = signer();
        let mut first = unsigned(node.node_id());
        first.ts = NOW;
        node.sign_call_registration(&mut first);
        write("call-registration-v1.json", json(&first));
        let mut second = second(unsigned(node.node_id()));
        second.ts = NOW;
        second.sfu_port = 3479;
        second.version = "0.1.4".into();
        second.caps = ["stun", "turn", "sfu", "cascade"].map(String::from).to_vec();
        second.load.participants = 3;
        second.load.max_participants = 768;
        node.sign_call_registration(&mut second);
        write("call-registration-v2.json", json(&second));

        let (root, list_key) = (signer(), signer());
        let delegation = root.delegate(&list_key.public_hex(), 1_950_000_000);
        let mut degraded = node_of(NodeId::of_key(b"b"), State::Degraded);
        degraded.sfu_port = 0;
        degraded.region = String::new();
        degraded.caps = vec!["stun".into(), "turn".into()];
        degraded.load = 0.5;
        let list = CallList {
            v: LIST_VERSION,
            kind: KIND.into(),
            complete: false,
            issued_at: 1_790_000_000,
            expires_at: 1_900_000_000,
            nodes: vec![node_of(NodeId::of_key(b"a"), State::Active), degraded],
        };
        write("call-list-root.pub", format!("{}\n", root.public_hex()));
        write("call-list-signed.json", json(&list_key.sign_call_list(&list, &delegation)));
    }
}
