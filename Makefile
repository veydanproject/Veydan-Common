# Veydan Common: the crates the services and the app share. A library:
# nothing is released but the tag.

.PHONY: build test check third-party clean

SHELL := /bin/bash
ENV := source scripts/env.sh &&

build:
	@$(ENV) cargo build

test:
	@$(ENV) cargo test

check:
	@$(ENV) cargo clippy --all-targets -- -D warnings

# THIRD-PARTY-LICENSES.md from Cargo.lock: run it after the lock changes.
third-party:
	@$(ENV) node scripts/third-party.mjs

clean:
	@rm -rf target
