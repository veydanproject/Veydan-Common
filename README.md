# Veydan Common

The crates the services of the Veydan network and the Veydan app share.
A library and nothing else: no binary, no release files; the tag of a
version is its release, and the services take the crates by that tag.

| Crate | What it is | Who reads it |
|---|---|---|
| `veydan-node` | who a node is: its id (the hash of its key), pinned TLS to it, h2 streams with one set of windows and pings, a node's own certificate chain, the key that signs, and the envelope of a signed list (the root delegates a list key, the list key signs) | VLink (bridge, client, hub), VCall, VCloud, the app |
| `veydan-denied` | the keys and the groups denied on every server of the network: the files Veydan Cloud lays on a host, and the one reader every server uses; also a list of keys a server writes itself (the members of a private server) | VPush, VGuard, VCloud |
| `registry-proto` | what bridges and call nodes say to the registry (registrations, states), the lists the registry signs for the clients, the hubs the root revoked | VLink, VHub, VCall, VRegistry, the app |

## Building

```sh
make build      # debug build
make test
make check      # clippy, warnings are errors
```

Inside the Veydan monorepo the folder is `services/common` and builds with
the project's toolchain; alone, with whatever `cargo` is on `PATH`
(`rust-toolchain.toml` names the version).

## How the services take it

In the monorepo every service names the crates by path
(`../common/crates/<crate>`). A snapshot of a service for its own
repository turns each of those paths into a dependency on this repository
by the tag of the version the monorepo holds, so a tag here is published
before the service that builds on it.

Every change to Common requires a new version in `Cargo.toml` and a new
Common release. Publish the snapshots of all services and products that use
Common again after that release, so their dependency tags match the new version.

## Versions

`CHANGELOG.md`. The version is the one of `Cargo.toml`
(`[workspace.package]`), the same for the three crates.

## Licence

PolyForm Perimeter 1.0.1, the licence of the whole project: `LICENSE`
(binding), `LICENSE-SUMMARY.md` (a plain-language summary). The crates it
is built from and their licences: `THIRD-PARTY-LICENSES.md`.

Developed by Rookbeam Technologies LLC, USA
