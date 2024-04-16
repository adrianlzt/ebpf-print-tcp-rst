# print-tcp-rst

Rust application that shows which applications are generating RST in a TCP connection.
It uses eBPF to trace the `tcp_send_reset` function and prints the PID and ports of the connection.

Example output (with RUST_LOG=info):
```
[2024-04-16T07:14:21Z INFO  print_tcp_rst] Waiting for Ctrl-C...
[2024-04-16T07:14:22Z ERROR print_tcp_rst] COMMAND=tcpserver PID=591456 SPORT=8080 DPORT=55538 tracepoint tcp:tcp_send_reset called
[2024-04-16T07:14:24Z ERROR print_tcp_rst] COMMAND=tcpserver PID=591456 SPORT=8080 DPORT=55550 tracepoint tcp:tcp_send_reset called
[2024-04-16T07:14:25Z INFO  print_tcp_rst] Exiting...
```

## Use
```bash
sudo ./print-tcp-rst
```

## Development

### Requirements
1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

### Build
Build eBPF module

```bash
cargo xtask build-ebpf
```

Build Userspace

```bash
cargo build
```

### Run

```bash
sudo RUST_LOG=info target/x86_64-unknown-linux-gnu/debug/print-tcp-rst
```

### Create release
```bash
cargo xtask build-ebpf --release
cargo build --release
```

Static binary will be in: `target/x86_64-unknown-linux-gnu/release/print-tcp-rst`
