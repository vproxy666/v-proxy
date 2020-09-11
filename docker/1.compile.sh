#!/bin/bash

# https://github.com/rust-embedded/cross

cross +stable build --target armv7-unknown-linux-musleabihf --release
mkdir -p ./bin/linux/arm/v7
cp -f ../target/armv7-unknown-linux-musleabihf/release/v-proxy ./bin/linux/arm/v7/v-proxy


cross +stable build --target aarch64-unknown-linux-musl --release
mkdir -p ./bin/linux/arm64
cp -f ../target/aarch64-unknown-linux-musl/release/v-proxy ./bin/linux/arm64/v-proxy


cross +stable build --target x86_64-unknown-linux-musl --release
mkdir -p ./bin/linux/amd64
cp -f ../target/x86_64-unknown-linux-musl/release/v-proxy ./bin/linux/amd64/v-proxy



