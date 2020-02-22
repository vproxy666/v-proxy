# Compilation Instructions


## Prerequisites

* Rust & Cargo on Ubuntu
* `sudo apt install docker.io mingw-w64 musl-tools`
* `sudo usermod -a -G docker $USER` (Relogin SSH terminal is required)
* `sudo systemctl start docker`
* `cargo install cross`

```
cat >>~/.cargo/config <<EOF
[target.x86_64-pc-windows-gnu]
linker = "/usr/bin/x86_64-w64-mingw32-gcc"
EOF
```



## Debug 

```
export RUST_LOG=info
cargo run -- --http_port=8887 --https_port=8888 --web_root=/home/v-proxy/docker/web
```


# Build for Windows x64

```
cross +stable build --target x86_64-pc-windows-gnu --release
```

# Build for GNU Linux x64
```
cross +stable build --target x86_64-unknown-linux-gnu --release
```

# Build for Alpine Linux x64
```
cross +stable build --target x86_64-unknown-linux-musl --release
```
