# remote-access

Minimal-intervention CLI to forward TCP/UDP traffic between two private networks through a public relay.

The relay can be reached over:
- QUIC (recommended, UDP-based)
- TCP

Both peers connect out to the relay (no inbound NAT rules needed on private hosts), pair with a shared session token, and forward traffic.

## Why Rust

This project is implemented in Rust for:
- predictable performance and low runtime overhead,
- memory safety without GC pauses,
- explicit ownership and bounded allocations in hot paths,
- good async networking support (`tokio`, `quinn`).

## High-level architecture

There are 3 processes:

1. **Server (relay)**: public VM with internet-reachable IP.
2. **Export peer**: machine that has access to the private target service.
3. **Import peer**: machine that exposes a local listener for users/apps.

Flow:
- `export` and `import` both connect to `server`.
- both send `Join { session, role }`.
- relay pairs matching peers by `session`.
- relay forwards framed messages between them:
  - open/close stream
  - TCP payload
  - UDP payload

## Features

- TCP transport to relay (`--transport tcp`)
- QUIC transport to relay (`--transport quic`)
- TCP port forwarding (core use case)
- Optional UDP forwarding (one active peer socket on import side)
- Session token pairing (`--session`)
- Dev TLS auto-generation for QUIC relay (`--auto-tls`)
- Optional direct peer-to-peer data path with relay signaling (`--data-path p2p`)

## Build

```bash
cargo build --release
```

Binary:

```bash
./target/release/remote-access
```

## CLI overview

```bash
remote-access --help
remote-access server --help
remote-access export --help
remote-access import --help
```

## Quick start (QUIC)

Use QUIC unless you have a reason to force TCP.

### 1) Start relay on public VM

```bash
remote-access server \
  --listen 0.0.0.0:7844 \
  --transport quic \
  --auto-tls
```

This writes `ra-dev-cert.pem` and `ra-dev-key.pem` in the working directory (if missing).

Open firewall/security group for **UDP 7844**.

### 2) Start export peer (private machine with target service)

Example: target service is local Postgres on `127.0.0.1:5432`.

```bash
remote-access export \
  --server RELAY_PUBLIC_IP:7844 \
  --transport quic \
  --trust-cert /path/to/ra-dev-cert.pem \
  --session my-shared-session \
  --to 127.0.0.1:5432
```

### 3) Start import peer (private machine where user connects)

Expose local port `15432` that forwards to export target.

```bash
remote-access import \
  --server RELAY_PUBLIC_IP:7844 \
  --transport quic \
  --trust-cert /path/to/ra-dev-cert.pem \
  --session my-shared-session \
  --listen 127.0.0.1:15432
```

Now local clients on import machine connect to `127.0.0.1:15432`.

## TCP transport mode

If UDP is blocked, use TCP transport between peers and relay:

```bash
remote-access server --listen 0.0.0.0:7844 --transport tcp
remote-access export --server RELAY_PUBLIC_IP:7844 --transport tcp --session my-shared-session --to 127.0.0.1:5432
remote-access import --server RELAY_PUBLIC_IP:7844 --transport tcp --session my-shared-session --listen 127.0.0.1:15432
```

## Peer-to-peer data path (relay signaling)

Use the relay for session signaling/pairing, then send tunnel traffic directly between peers.

`import` must expose a reachable TCP socket for `export` to connect.

```bash
remote-access import \
  --server RELAY_PUBLIC_IP:7844 \
  --transport quic \
  --trust-cert /path/to/ra-dev-cert.pem \
  --session my-shared-session \
  --data-path p2p \
  --p2p-listen 0.0.0.0:39000 \
  --p2p-advertise IMPORT_PUBLIC_IP:39000 \
  --listen 127.0.0.1:15432
```

```bash
remote-access export \
  --server RELAY_PUBLIC_IP:7844 \
  --transport quic \
  --trust-cert /path/to/ra-dev-cert.pem \
  --session my-shared-session \
  --data-path p2p \
  --to 127.0.0.1:5432
```

Notes:
- Keep relay transport (`--transport`) open for signaling.
- `--p2p-listen` is required on `import` when `--data-path p2p` is enabled.
- If the address to announce differs from the local bind address, set `--p2p-advertise`.
- If direct connection cannot be established before timeout, peers exit with an error.

## UDP forwarding

Enable UDP forwarding by setting both sides:

- export: `--udp-target HOST:PORT`
- import: `--udp-listen HOST:PORT`

Both peers for the same session must agree on UDP enabled/disabled.

Example:

```bash
remote-access export \
  --server RELAY_PUBLIC_IP:7844 \
  --transport quic \
  --trust-cert /path/to/ra-dev-cert.pem \
  --session my-udp-session \
  --to 127.0.0.1:0 \
  --udp-target 127.0.0.1:9000

remote-access import \
  --server RELAY_PUBLIC_IP:7844 \
  --transport quic \
  --trust-cert /path/to/ra-dev-cert.pem \
  --session my-udp-session \
  --listen 127.0.0.1:0 \
  --udp-listen 127.0.0.1:9000
```

## Deploy relay as a service (systemd)

Example unit:

```ini
[Unit]
Description=remote-access relay
After=network-online.target
Wants=network-online.target

[Service]
User=remote-access
Group=remote-access
WorkingDirectory=/var/lib/remote-access
ExecStart=/usr/local/bin/remote-access server --listen 0.0.0.0:7844 --transport quic --auto-tls
Restart=on-failure
RestartSec=3
Environment=RUST_LOG=info

[Install]
WantedBy=multi-user.target
```

Remember to allow UDP 7844 in cloud firewall + host firewall.

## Security notes

- `--auto-tls` is convenient for dev/testing (self-signed cert).
- For production:
  - use a proper certificate/key pair (`--cert`, `--key`),
  - pin trust carefully on clients (`--trust-cert`),
  - restrict relay firewall rules if possible,
  - use strong random `--session` values.

## Troubleshooting

- **QUIC fails to connect**
  - check UDP port is open end-to-end.
  - verify `--trust-cert` points to relay cert.
  - if cert SAN mismatch, set `--server-name` explicitly.

- **Session not pairing**
  - ensure both sides use exact same `--session`.
  - ensure both sides agree on UDP enabled/disabled.
  - ensure both sides use same `--data-path` setting.

- **No traffic through tunnel**
  - verify `export --to` points to reachable local target.
  - test target locally on export machine first.

## Current limitations

- No authentication beyond session token pairing.
- Relay keeps session pairing state in-memory.
- UDP mode currently maps to one active remote peer socket on import side.

