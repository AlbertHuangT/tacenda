# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm install                  # install deps (includes wrangler)
npm run dev                  # local dev via wrangler (http://localhost:8787)
npm run deploy               # deploy to Cloudflare Workers
node server.js               # legacy local Node.js server (ws://localhost:3000)
```

**First-time Cloudflare setup:**
```bash
npx wrangler login           # authenticate with Cloudflare
npm run deploy               # creates the Worker and Durable Object on first run
```

> Durable Objects require the **Workers Paid plan** ($5/month). The free tier does not support them.

## Architecture

Two-file app, no framework, no database, no persistent storage of any kind.

### Server (`server.js`)

Node.js WebSocket server on port 3000. Maintains one in-memory `Map<publicKeyBase64, WebSocket>` as a routing table — nothing else.

**Protocol (two message types):**
- `{ type: "register", publicKey }` — client announces its public key as its address; server adds it to the map
- `{ type: "message", to, payload, senderKey? }` — server looks up `to` in the map and forwards the envelope verbatim; sends `{ type: "error" }` back if recipient isn't online

Disconnect removes the entry immediately. Server never reads `payload` content.

### Client (`public/index.html`)

Single HTML file, all JS inline. No dependencies.

**Startup:** generates an RSA-OAEP 2048-bit key pair via Web Crypto API, exports the public key as base64 SPKI, then registers with the server. The private key is a `CryptoKey` object — never serialized, destroyed with the page.

**Encryption scheme (hybrid):**
1. Generate a random AES-GCM-256 key + 12-byte IV
2. Encrypt the plaintext with AES-GCM
3. Wrap the AES key with the recipient's RSA public key (RSA-OAEP)
4. Send `{ k, iv, msg }` (all base64) — this fits RSA's 190-byte limit while supporting arbitrary message lengths

**Routing:** each user's public key *is* their address. User A pastes User B's public key → messages are addressed `to: UserB.publicKeyBase64`.

**Key exchange:** the first outbound message includes `senderKey: myPublicKeyBase64`. When the recipient receives it, their client auto-populates the reply-to field — no manual copy/paste needed for the response direction.
