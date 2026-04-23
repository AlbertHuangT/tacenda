# RSA Encrypted Chat

End-to-end encrypted messaging with zero server-side state. No accounts, no logs, no persistent storage of any kind.

**Live:** [ppb1s0n.us.kg](https://ppb1s0n.us.kg)

---

## How it works

The server is a router, not a vault. It maintains an in-memory table mapping public keys to active WebSocket connections. When a message is sent, the server forwards an encrypted blob to the recipient's socket — nothing more. The decryption key never leaves the sender's device.

Each page load generates a fresh **RSA-2048** key pair via the Web Crypto API. Your public key is your address. When you close the tab, the private key is gone.

### Encryption scheme

RSA-OAEP alone cannot encrypt arbitrary-length data (~190-byte ceiling for 2048-bit keys). The system uses hybrid encryption:

1. A random **AES-GCM-256** key and 12-byte IV are generated per message.
2. The plaintext is encrypted with AES-GCM.
3. The AES key is wrapped with the recipient's RSA-2048-OAEP public key.
4. Three base64 fields — `k`, `iv`, `msg` — are transmitted and forwarded verbatim by the server.

### Long-term identity (optional)

For recurring contacts, generate a persistent identity key pair and exchange your public key once, offline. To start a session, broadcast a **handshake**: your current session public key encrypted with your contact's long-term public key. Every connected client silently attempts decryption; only the intended recipient succeeds. The server never learns who is signaling whom.

Identity key operations are **CLI-only**. Web clients execute JavaScript delivered by the server at runtime — a compromised server could inject code to exfiltrate a loaded private key. A compiled CLI binary is auditable, static, and immune to that class of attack.

---

## Pages

| Path | Description |
|------|-------------|
| `/` | Landing page — explanation and documentation |
| `/chat` | Chat interface |
| `/keygen` | Browser-based identity key generator |

---

## Deployment

### Cloudflare Workers (recommended)

Requires the **Workers Paid plan** ($5/month) for Durable Objects.

```bash
npm install
npx wrangler login
npm run deploy
```

The Durable Object keeps the routing table in memory for the lifetime of the instance. Nothing is written to disk or KV storage.

### Local (Node.js)

```bash
npm install
node server.js        # serves on http://localhost:3000
```

For a public URL without deploying to Cloudflare, use the included tunnel config:

```bash
cloudflared tunnel run
```

The tunnel is configured in `cloudflared.yml`.

---

## CLI

The Go CLI client supports long-term identity keys and background operation.

```bash
# build
cd cli && go build -o rsa-chat-cli .

# generate a long-term identity key pair (run once)
./rsa-chat-cli --keygen --out ~/.rsa-chat/identity.pem

# connect
./rsa-chat-cli --key ~/.rsa-chat/identity.pem \
               --server wss://ppb1s0n.us.kg/ws

# commands
/find <long_term_public_key>   broadcast a handshake to a contact
/accept <n>                    accept an incoming handshake
/contacts                      list known contacts
/chat <n>                      switch active contact
/mykey                         print your current session public key
/quit                          exit
```

The CLI is fully interoperable with the web client — messages sent from either can be decrypted by the other.

---

## File structure

```
├── public/
│   ├── index.html      landing page
│   ├── chat.html       chat interface
│   └── keygen.html     identity key generator
├── cli/
│   ├── main.go         Go CLI client
│   └── go.mod
├── worker.js           Cloudflare Worker + Durable Object
├── server.js           Node.js WebSocket server (local/tunnel)
├── wrangler.toml       Cloudflare deployment config
└── cloudflared.yml     Cloudflare Tunnel config
```

---

## Security properties

| Property | Status |
|----------|--------|
| Server reads message content | Never |
| Server stores encryption keys | Never |
| Session keys persist across reloads | Never |
| Identity private keys leave the device | Never |
| Server knows who is talking to whom (direct messages) | Routing address only (public key) |
| Server knows who is signaling whom (handshake broadcast) | No — broadcast to all |

---

## License

MIT License — see [LICENSE](LICENSE).

You are free to use, modify, distribute, and sell this software, including in commercial products. The only requirement is that you **keep the copyright notice** (`Copyright (c) 2026 Huang`) in all copies or substantial portions of the software.

This project was originally created by **Huang**.
