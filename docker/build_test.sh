#!/bin/bash

cp -f ../target/x86_64-unknown-linux-musl/release/v-proxy ./v-proxy
sudo docker build -t="vproxy/server:test" .
sudo docker push vproxy/server:test



