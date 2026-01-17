# whspr

End-to-end encrypted terminal chat over QUIC.

## Features

- **End-to-end encryption** - Double Ratchet protocol (Signal-style) with forward secrecy
- **QUIC transport** - Modern, fast, multiplexed connections with built-in TLS 1.3
- **Deterministic usernames** - Identity derived from public key (e.g., `brave-falcon`)
- **Offline messaging** - Server queues messages for offline users (24h TTL)
- **Terminal UI** - Multi-pane interface with conversation tabs

## Installation

### From releases

Download binaries from [GitHub Releases](../../releases).

### From source

```bash
# Clone
git clone https://github.com/yourusername/whspr.git
cd whspr

# Build
cargo build --release

# Binaries at:
# ./target/release/whspr        (client)
# ./target/release/whspr-server (server)
```

### Cross-compilation

```bash
make install-deps  # Install tooling
make linux         # Linux (static musl)
make windows       # Windows
make dist          # All platforms
```

## Usage

### Server

```bash
# Default: listens on 0.0.0.0:4433
./whspr-server

# Or with Docker
docker compose up -d
```

Environment variables:
| Variable | Default | Description |
|----------|---------|-------------|
| `WHSPR_LISTEN_ADDR` | `0.0.0.0:4433` | Bind address |
| `WHSPR_DB_PATH` | `whspr.db` | SQLite database path |
| `WHSPR_MESSAGE_TTL` | `86400` | Offline message TTL (seconds) |

### Client

```bash
# Connect to server
./whspr 127.0.0.1:4433

# Or remote server
./whspr chat.example.com:4433
```

Your identity key is stored at `~/.whspr_key` (created on first run).

## Commands

| Command | Description |
|---------|-------------|
| `/add <username>` | Add contact and start conversation |
| `/quit` or `/q` | Exit |
| `Tab` | Switch between conversations |
| `Ctrl+C` | Exit |

Type a message and press `Enter` to send.

## Architecture

```
┌─────────────┐         QUIC/TLS 1.3        ┌─────────────┐
│   Client    │◄──────────────────────────►│   Server    │
│  (whspr)    │    Double Ratchet E2EE      │             │
└─────────────┘                             └─────────────┘
      │                                           │
      │ ~/.whspr_key                              │ whspr.db
      │ (Ed25519 + X25519)                        │ (SQLite)
      ▼                                           ▼
   Identity                                  User Store
   Storage                                   Message Queue
```

### Crates

- `whspr-protocol` - Wire protocol, crypto, identity
- `whspr-server` - QUIC server, user store, message routing
- `whspr-client` - TUI client, state management

### Cryptography

- **Identity**: Ed25519 (signing) + X25519 (key exchange)
- **Key exchange**: X3DH (Extended Triple Diffie-Hellman)
- **Message encryption**: Double Ratchet with AES-256-GCM
- **Key derivation**: HKDF-SHA256

## Security Notes

This is a prototype. Known limitations:

- Self-signed TLS certificates (no certificate pinning)
- No authentication challenge-response on registration
- Key file stored unencrypted
- No audit of cryptographic implementation

Do not use for sensitive communications without addressing these issues.

## License

MIT
