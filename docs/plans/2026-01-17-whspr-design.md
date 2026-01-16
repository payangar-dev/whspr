# whspr Design Document

Ephemeral, end-to-end encrypted terminal chat.

## Overview

| Aspect | Decision |
|--------|----------|
| Architecture | Client-Server (separate binaries) |
| Transport | QUIC via `quinn` (built-in TLS 1.3) |
| E2E Encryption | Double Ratchet (forward secrecy) |
| Group Encryption | Sender Keys |
| Identity | Ed25519 keypair, key-based auth |
| Usernames | Deterministic from pubkey (`adjective-animal`) |
| Message Delivery | Store-and-forward with configurable TTL |
| Persistence | Server: SQLite for users. Client: none (ephemeral) |
| TUI | Multi-tab `ratatui`, vim-style keys |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      whspr-server                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ User        │  │ Message     │  │ Connection          │  │
│  │ Registry    │  │ Queue       │  │ Manager             │  │
│  │ (usernames  │  │ (encrypted  │  │ (QUIC sessions,     │  │
│  │  + pubkeys) │  │  + TTL)     │  │  multiplexed)       │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           ▲
                           │ QUIC (TLS 1.3 built-in)
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     ┌─────────┐      ┌─────────┐      ┌─────────┐
     │ Client  │      │ Client  │      │ Client  │
     │ @alice  │      │ @bob    │      │ @carol  │
     └─────────┘      └─────────┘      └─────────┘
```

**Two layers of encryption**:
- QUIC's TLS 1.3 protects client-server transport
- Double Ratchet protects message content end-to-end (server can't read)

## Cryptography

### Identity Keys

Generated once, stored locally:
- Ed25519 keypair for signing/identity
- X25519 keypair derived for key exchange
- Username derived deterministically from public key

### Username Generation

```
pubkey_bytes → SHA256 → first 2 bytes pick adjective
                      → next 2 bytes pick animal

Example: ed25519_pubkey → "brave-falcon"
```

~500 adjectives × ~200 animals = 100k unique combinations.

### Double Ratchet (1-on-1 chats)

```
Initial key exchange (X3DH-style):
  Alice fetches Bob's public keys from server
  Alice generates ephemeral X25519 keypair
  Shared secret derived from: Alice_ephemeral × Bob_identity

Per-message ratchet:
  Each message advances the ratchet
  New symmetric key per message
  Compromised key doesn't expose past messages
```

### Sender Keys (group chats)

```
Group creation:
  Creator generates group ID + initial Sender Key
  Distributes Sender Key to members (via Double Ratchet DMs)

Sending to group:
  Encrypt message once with Sender Key
  Server fans out to all group members
  Sender Key rotates periodically or on member removal
```

### Crates

- `x25519-dalek` — X25519 key exchange
- `ed25519-dalek` — Ed25519 signatures
- `aes-gcm` — Symmetric encryption
- `hkdf` + `sha2` — Key derivation

## Wire Protocol

Binary message format with minimal overhead:

```
┌──────────────────────────────────────────────────────┐
│  Header (fixed 8 bytes)                              │
│  ┌────────────┬────────────┬────────────────────┐    │
│  │ msg_type   │ flags      │ payload_length     │    │
│  │ (1 byte)   │ (1 byte)   │ (4 bytes, big-end) │    │
│  └────────────┴────────────┴────────────────────┘    │
├──────────────────────────────────────────────────────┤
│  Payload (variable, up to 64KB)                      │
│  MessagePack-encoded structured data                 │
└──────────────────────────────────────────────────────┘
```

### Message Types

| Type | Code | Direction | Purpose |
|------|------|-----------|---------|
| `Register` | 0x01 | C→S | Register username + public keys |
| `Auth` | 0x02 | C→S | Authenticate with signature challenge |
| `AuthOk` | 0x03 | S→C | Authentication successful |
| `LookupUser` | 0x10 | C→S | Fetch user's public keys |
| `UserInfo` | 0x11 | S→C | Response with public keys |
| `Send` | 0x20 | C→S | Encrypted message to recipient |
| `Receive` | 0x21 | S→C | Incoming encrypted message |
| `Ack` | 0x22 | C→S | Message received acknowledgment |
| `Presence` | 0x30 | Both | Online/offline status |
| `GroupCreate` | 0x40 | C→S | Create group chat |
| `GroupInvite` | 0x41 | C→S | Add member to group |
| `GroupMsg` | 0x42 | Both | Encrypted group message |

Payloads encoded with MessagePack via `rmp-serde`.

## Client TUI

```
┌─────────────────────────────────────────────────────────────┐
│ whspr @alice                              ● online   [?]help│
├────────────────┬────────────────────────────────────────────┤
│ Conversations  │ @bob  │ @carol  │ #project                 │
│                ├────────────────────────────────────────────┤
│ ● @bob         │ bob: hey, you around?                      │
│   @carol       │ alice: yeah what's up                      │
│ ● #project     │ bob: check out this thing                  │
│   #random      │ alice: nice                                │
│                │                                            │
│ ──────────     │                                            │
│ Requests (2)   │                                            │
│   @dave        │                                            │
│   @eve         │                                            │
├────────────────┼────────────────────────────────────────────┤
│ > type here... │                                       [TAB]│
└────────────────┴────────────────────────────────────────────┘
```

### Layout

- Left sidebar: conversation list (DMs and groups), contact requests
- Top tabs: switch between open conversations
- Main area: message history (in-memory only)
- Bottom: input line

### Key Bindings

- `Tab` / `Shift+Tab`: cycle conversations
- `Ctrl+N`: new conversation
- `Ctrl+G`: create group
- `/command`: slash commands (`/add @user`, `/leave`, `/quit`)
- `Esc`: cancel/back

### Async Architecture

`tokio` runtime, UI runs on main thread, network I/O on background tasks. Channels (`tokio::sync::mpsc`) connect them.

## Server Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     whspr-server                            │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ QUIC Listener (quinn)                                │   │
│  │ - Accepts connections                                │   │
│  │ - Spawns task per connection                         │   │
│  └──────────────────────────────────────────────────────┘   │
│                          │                                  │
│                          ▼                                  │
│  ┌──────────────────────────────────────────────────────┐   │
│  │ Connection Handler                                   │   │
│  │ - Authenticates client                               │   │
│  │ - Manages bidirectional streams                      │   │
│  │ - Routes messages to recipients                      │   │
│  └──────────────────────────────────────────────────────┘   │
│          │                │                │                │
│          ▼                ▼                ▼                │
│  ┌────────────┐   ┌──────────────┐   ┌────────────────┐     │
│  │ UserStore  │   │ MessageQueue │   │ SessionMap     │     │
│  │ (SQLite)   │   │ (in-memory   │   │ (in-memory)    │     │
│  │            │   │  + TTL)      │   │                │     │
│  │ - username │   │ - pending    │   │ - user→conn    │     │
│  │ - pubkeys  │   │   messages   │   │   mapping      │     │
│  │ - created  │   │ - expiry     │   │ - presence     │     │
│  └────────────┘   └──────────────┘   └────────────────┘     │
└─────────────────────────────────────────────────────────────┘
```

### Storage

- `UserStore`: SQLite for persistence (pubkeys + derived names survive restart)
- `MessageQueue`: In-memory with TTL — messages expire, no disk traces
- `SessionMap`: In-memory — tracks who's online, routes messages

### Message Routing

1. Client sends encrypted blob to server
2. Server looks up recipient in SessionMap
3. If online → forward immediately via their QUIC stream
4. If offline → queue with TTL (configurable, default 24h)
5. On reconnect → drain queued messages

## Project Structure

```
whspr/
├── Cargo.toml              # workspace root
├── crates/
│   ├── whspr-protocol/     # shared types, wire format, crypto
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── message.rs      # message types + serialization
│   │   │   ├── crypto.rs       # double ratchet, sender keys
│   │   │   ├── identity.rs     # keypair, username generation
│   │   │   └── frame.rs        # wire framing
│   │   └── Cargo.toml
│   │
│   ├── whspr-server/       # server binary
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── connection.rs   # QUIC connection handling
│   │   │   ├── store.rs        # SQLite user store
│   │   │   ├── queue.rs        # TTL message queue
│   │   │   └── session.rs      # online user tracking
│   │   └── Cargo.toml
│   │
│   └── whspr-client/       # client binary
│       ├── src/
│       │   ├── main.rs
│       │   ├── tui/            # ratatui UI components
│       │   ├── net.rs          # QUIC client, message handling
│       │   ├── state.rs        # app state, conversations
│       │   └── commands.rs     # slash command parsing
│       └── Cargo.toml
│
└── wordlists/
    ├── adjectives.txt
    └── animals.txt
```

## Dependencies

| Crate | Purpose |
|-------|---------|
| `quinn` | QUIC transport |
| `rustls` | TLS for QUIC |
| `tokio` | Async runtime |
| `ratatui` + `crossterm` | Terminal UI |
| `x25519-dalek`, `ed25519-dalek` | Key exchange, signatures |
| `aes-gcm`, `hkdf`, `sha2` | Symmetric crypto, KDF |
| `rmp-serde` | MessagePack serialization |
| `sqlx` | SQLite for server |
| `tracing` | Logging |

## Security Properties

**What the server sees**: Encrypted blobs, usernames, public keys, online status. Never plaintext.

**What survives restart**:
- Server: user registry (pubkeys + derived names)
- Client: keypair file only — no message history

**Forward secrecy**: Compromising current keys doesn't expose past messages.

**No persistence on client**: Messages exist only in memory. Close the app, history is gone.
