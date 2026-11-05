//! What a hub and the registry say to each other, since the registry
//! left the hub (vregistry 0.1.0, vhub 0.3.0).
//!
//! The hub holds the links and the certificate the bridges trust; the
//! registry judges. So the hub reports and the registry decides:
//!
//! ```text
//! GET  /vlink/v1/hub/bridges   HubBridges: the bridges to dial, and the
//!                              new ones to look at once        (hubs)
//! POST /vlink/v1/hub/links     HubLinks: how the links are doing, and
//!                              which new bridges proved their key (hubs)
//! ```
//!
//! Both show the hub token. A hub of 0.2.x reads `HubBridges` as
//! `bridge::Bridges` (it never saw `new`) and never posts: such a hub's
//! bridges are dialled but prove nothing to the registry, so both hubs
//! of the network move to 0.3.0 in one go.

use serde::{Deserialize, Serialize};

use crate::{NodeId, NodeRef};

/// The registry's answer to a hub: what to dial, and what to look at.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubBridges {
    /// Every bridge from VERIFIED on: the hub keeps a link to each.
    pub bridges: Vec<NodeRef>,
    /// Bridges that reported in and nobody has dialled yet: the hub dials
    /// each once, as a hub would, and says in its next report whether
    /// the bridge held the key of its id (`HubLink::seen`). No link is
    /// kept for one of these.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new: Vec<NodeRef>,
}

/// One hub's word on one bridge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubLink {
    pub bridge: NodeId,
    /// The link carries bytes both ways right now (a bridge the hub was
    /// given to dial). False for one just looked at.
    #[serde(default)]
    pub up: bool,
    /// The hub dialled the bridge and it proved the key of its id (one of
    /// `HubBridges::new`); `None` when the hub did not try this tick,
    /// `Some(false)` when the dial-back failed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seen: Option<bool>,
}

/// A hub's report, every tick: which links it holds and how they are.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubLinks {
    /// The hub's name, as in its config (`eu-1`): the registry keeps the
    /// word of each hub apart, so one hub's dropped link does not undo
    /// another's.
    pub hub: String,
    #[serde(default)]
    pub links: Vec<HubLink>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::Bridges;

    fn node(n: u8) -> NodeRef {
        NodeRef { addr: ([203, 0, 113, n], 443).into(), id: NodeId([n; 32]), sni: None }
    }

    #[test]
    fn a_hub_of_0_2_reads_the_answer_as_the_plain_list_of_bridges() {
        let answer = HubBridges { bridges: vec![node(1), node(2)], new: vec![node(3)] };
        let text = serde_json::to_string(&answer).unwrap();
        let old: Bridges = serde_json::from_str(&text).unwrap();
        assert_eq!(old.bridges, answer.bridges);
        // And the other way: an answer without `new` is one with none.
        let plain = serde_json::to_string(&Bridges { bridges: vec![node(1)] }).unwrap();
        let read: HubBridges = serde_json::from_str(&plain).unwrap();
        assert_eq!(read, HubBridges { bridges: vec![node(1)], new: Vec::new() });
        assert!(!text.contains("\"new\"") || !answer.new.is_empty());
        assert!(!serde_json::to_string(&HubBridges::default()).unwrap().contains("new"));
    }

    #[test]
    fn a_report_says_what_was_seen_and_what_was_not_tried() {
        let report = HubLinks {
            hub: "eu-1".into(),
            links: vec![
                HubLink { bridge: NodeId([1; 32]), up: true, seen: None },
                HubLink { bridge: NodeId([3; 32]), up: false, seen: Some(true) },
            ],
        };
        let text = serde_json::to_string(&report).unwrap();
        assert_eq!(text.matches("\"seen\"").count(), 1, "{text}");
        let back: HubLinks = serde_json::from_str(&text).unwrap();
        assert_eq!(back, report);
        let least: HubLinks = serde_json::from_str(r#"{"hub":"us-1"}"#).unwrap();
        assert_eq!(least, HubLinks { hub: "us-1".into(), links: Vec::new() });
    }
}
