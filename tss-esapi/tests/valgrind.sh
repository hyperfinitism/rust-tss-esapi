#!/usr/bin/env bash

# Copyright 2022 Contributors to the Parsec project.
# SPDX-License-Identifier: Apache-2.0

# Script for running valgrind against the set of tests
# Intended for running in the Ubuntu container

set -euf -o pipefail

if [[ ! -z ${RUST_TOOLCHAIN_VERSION:+x} ]]; then
	rustup override set ${RUST_TOOLCHAIN_VERSION}
fi

##########################
# Install cargo-valgrind #
##########################
apt update
apt install -y valgrind
cargo install cargo-valgrind

#################
# Run the tests #
#################
RUST_BACKTRACE=1 RUST_LOG=info cargo valgrind test -- --nocapture
