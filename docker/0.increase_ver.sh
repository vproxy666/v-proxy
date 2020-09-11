#!/bin/bash

line="$(grep -oP '(?:pub\s+static\s+VERSION\s*\:\s*\&str\s*\=\s*\"[0-9]+\.[0-9]+\.)[0-9]+'  ../src/main.rs)"
minor=$((${line##*.}+1))
sed -i -E "s/(pub\s+static\s+VERSION\s*\:\s*\&str\s*\=\s*\"[0-9]+\.[0-9]+)[^\"]*/\1\.$minor/" ../src/main.rs
line="$(grep -oP '(?:pub\s+static\s+VERSION\s*\:\s*\&str\s*\=\s*\"[0-9]+\.[0-9]+\.)[0-9]+'  ../src/main.rs)"
version=${line##*\"}
sed -i -E "s/^(version\s*\=\s*\")[^\"]*/\1$version/" ../Cargo.toml