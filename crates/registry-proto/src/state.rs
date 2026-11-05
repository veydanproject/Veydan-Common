//! How far a node has come in the registry's eyes. One ladder for bridges
//! and call nodes: the proofs differ, the states do not.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Reported in; nobody has seen it prove its key yet.
    New,
    /// Reached, and its key proven. Not given to clients yet.
    Verified,
    /// Checked to work: given to clients.
    Active,
    /// A check failed; kept out of the lists until one succeeds.
    Degraded,
    /// Checks kept failing, or the node went silent.
    Dead,
    /// The admin's word.
    Banned,
}

impl State {
    /// The name on the wire: `new`, `verified`, `active`…
    pub fn as_str(&self) -> &'static str {
        match self {
            State::New => "new",
            State::Verified => "verified",
            State::Active => "active",
            State::Degraded => "degraded",
            State::Dead => "dead",
            State::Banned => "banned",
        }
    }
}

impl std::fmt::Display for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_name_is_the_one_on_the_wire() {
        for state in [State::New, State::Verified, State::Active, State::Degraded, State::Dead, State::Banned] {
            assert_eq!(serde_json::to_string(&state).unwrap(), format!("\"{state}\""));
        }
    }
}
