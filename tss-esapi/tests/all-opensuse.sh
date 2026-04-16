#!/usr/bin/env bash

# Copyright 2024 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# This script executes tests for the tss-esapi crate.
# It can be run inside the container which Dockerfile is in the same folder.
#
# Usage: ./tests/all.sh

set -euf -o pipefail

###################
# Build the crate #
###################
RUST_BACKTRACE=1 cargo build --features "generate-bindings integration-tests serde"

#################
# Run the tests #
#################
RUST_BACKTRACE=1 RUST_LOG=info cargo test --features "generate-bindings integration-tests serde" -- --nocapture
