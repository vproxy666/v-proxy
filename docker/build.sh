#!/bin/bash

line="$(grep -oP '(?:pub\s+static\s+VERSION\s*\:\s*\&str\s*\=\s*\"[0-9]+\.[0-9]+\.)[0-9]+'  ../src/main.rs)"
minor=$((${line##*.}+1))
sed -i -E "s/(pub\s+static\s+VERSION\s*\:\s*\&str\s*\=\s*\"[0-9]+\.[0-9]+)[^\"]*/\1\.$minor/" ../src/main.rs
line="$(grep -oP '(?:pub\s+static\s+VERSION\s*\:\s*\&str\s*\=\s*\"[0-9]+\.[0-9]+\.)[0-9]+'  ../src/main.rs)"
version=${line##*\"}
sed -i -E "s/^(version\s*\=\s*\")[^\"]*/\1$version/" ../Cargo.toml

cross +stable build --target x86_64-unknown-linux-musl --release

cp -f ../target/x86_64-unknown-linux-musl/release/v-proxy ./v-proxy
sudo docker build -t="vproxy/server:latest" .
sudo docker push "vproxy/server:$version"
sudo docker push vproxy/server:latest



