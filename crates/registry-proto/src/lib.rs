//! What the registry of the Veydan network takes and says.
//!
//! The registry is the directory of the volunteer nodes: bridges (VLink)
//! and call nodes (VCall). A node reports in with a registration its own
//! key signed; the registry checks the node, keeps its state, and hands
//! the clients a signed list of the nodes worth using. The lists are
//! signed in two steps (`veydan_node::list`): the root delegates a list
//! key, the list key signs.
//!
//! - `state`: how far a node has come in the registry's eyes;
//! - `bridge`: the registration and the list of bridges;
//! - `call`: the registration and the list of call nodes;
//! - `hub`: what a hub reports to the registry, and what it is told to dial;
//! - `revoke`: the hubs the root no longer stands behind;
//! - `sign`: what the keys of the servers sign, over `veydan_node::sign::Signer`.
//!
//! One copy for every side: the node, the registry, the hub, the client
//! and the checks of vcloud all read this crate.

pub mod bridge;
pub mod call;
pub mod hub;
pub mod revoke;
pub mod sign;
pub mod state;

pub use state::State;
pub use veydan_node::list::{Delegation, Error as ListError, SignedList};
pub use veydan_node::{NodeId, NodeRef};
