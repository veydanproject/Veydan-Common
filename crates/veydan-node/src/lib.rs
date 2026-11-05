//! Who a node of the Veydan network is, and how it is called.
//!
//! A bridge (VLink), a hub, a call node (VCall), the agent of vcloud: each
//! is a key, kept from its first start, whose hash is its id. The TLS it
//! serves runs on another key, under a certificate the node's key signed;
//! whoever calls pins the id and accepts nothing else. On top of TLS the
//! nodes speak h2, with one set of windows and pings for every connection.
//!
//! - `id`: the id and the address of a node;
//! - `pin`: calling a node, its key pinned;
//! - `io`: an h2 stream as a byte pipe, and the h2 settings;
//! - `tls`: a node's own certificate chain and key;
//! - `sign`: a key that signs — the root, a list key, a node's key;
//! - `list`: a signed list as it travels, and the check of its signatures.
//!
//! What a registry says and takes (registrations, the lists themselves)
//! is `registry-proto`, built on this crate. The words of one network
//! (bridge, hub) are in `vlink-proto`; this crate knows nodes only.

pub mod error;
pub mod id;
pub mod io;
pub mod list;
pub mod pin;
pub mod sign;
pub mod tls;

pub use error::Error;
pub use id::{NodeId, NodeRef};
pub use io::H2Stream;

/// Certificate and key types, so that the crates above need no rustls of their own.
pub use rustls::pki_types as rustls_types;
