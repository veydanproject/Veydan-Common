#!/usr/bin/env bash
# Build environment of Veydan Common — meant to be *sourced*.
#
# Inside the Veydan monorepo (this folder is services/<name> there) the
# project-local toolchain is used; VEYDAN_TOOLCHAINS says where it is, the
# one place that knows. Anywhere else, whatever cargo is on PATH.

VCOMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export VCOMMON_DIR

VEYDAN_TOOLCHAINS="${VEYDAN_TOOLCHAINS:-$VCOMMON_DIR/../../data/toolchains}"
if [ -x "$VEYDAN_TOOLCHAINS/cargo/bin/cargo" ]; then
  VCOMMON_TOOLS="$(cd "$VEYDAN_TOOLCHAINS" && pwd)"
  export RUSTUP_HOME="$VCOMMON_TOOLS/rustup"
  export CARGO_HOME="$VCOMMON_TOOLS/cargo"
  export PATH="$CARGO_HOME/bin:$PATH"
else
  VCOMMON_TOOLS="$VCOMMON_DIR/.tools"
fi
export VCOMMON_TOOLS

if ! command -v cargo >/dev/null 2>&1; then
  echo "veydan-common: cargo not found; install Rust from https://rustup.rs" >&2
  return 1 2>/dev/null || exit 1
fi
