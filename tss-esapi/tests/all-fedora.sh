#!/usr/bin/env bash

# Copyright 2019 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

set -euf -o pipefail

if [[ ! -z ${USE_FROZEN_LOCKFILE:+x} ]]; then
	# Some versions of Fedora that are used during testing are old
    # so in order to prevent any drift from the versions available
    # in the old versions the frozen Cargo lock is used.
	cp tests/Cargo.lock.frozen ../Cargo.lock
fi

###################
# Build the crate #
###################
RUST_BACKTRACE=1 cargo build --features "generate-bindings integration-tests serde"

#################
# Run the tests #
#################
RUST_BACKTRACE=1 RUST_LOG=info cargo test --features "generate-bindings integration-tests serde" -- --nocapture
