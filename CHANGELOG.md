# Changelog

## 0.1.1 (2026-11-06): one key validator for revoked hubs

- `registry-proto` uses `veydan-denied::is_key` for revoked hub keys, so
  the shared key format has one implementation.
- The workspace's minimum Rust version matches the repository toolchain.

## 0.1.0 (2026-11-04): the crates the services share, in a folder of their own

- `veydan-node`: what was the general part of `vlink-proto` 0.3.5 — the id
  of a node (`BridgeId` → `NodeId`, `BridgeRef` → `NodeRef`), the pinned
  TLS to one (`pin`), the h2 streams and settings (`io`), a node's own
  chain and key (`tls::Identity`, `cert_from_pem`, `not_after`), the key
  that signs (`sign::Signer`, with a plain `sign` and `sign_list_as` in a
  named context) and the envelope of a signed list (`list::SignedList`
  with `verify_text`, `Delegation`, `hex`, `unhex`). `vlink-proto` 0.4.0
  gives it all under its old names.
- `veydan-denied`: `vpush-proto::denied` of VPush 0.5.1 as a crate of its
  own, read by VPush, VGuard and VCloud alike. New: `is_key`, `is_group_id`
  and `parse_as` are public, `check` judges a file as the readers do, and
  `KeyList` is a list of keys a server writes itself (`append`,
  `write_all`, `items`). An id of a group may not hold `#`: in a file it
  starts a comment.
- `registry-proto`: what the registry takes and says, one copy for every
  side — the states of a node, the registration and the signed list of
  bridges (from `vlink-proto::wire` and `::list`), the revoked hubs (from
  `vlink-proto::revoke`), the registration and the signed list of call
  nodes (`call`, one copy where the hub, the node and the client each had
  their own; golden vectors in `golden/`), and `sign::SignerExt` for the
  signatures of those forms. `hub`: what a hub and the registry say to
  each other once the registry is a service of its own (vregistry) — the
  bridges to dial and the new ones to look at (`HubBridges`), and the
  hub's report on its links and dial-backs (`HubLinks`).
