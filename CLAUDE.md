# CLAUDE.md

Guidance for Claude Code working in this repo.

## Deployment

**Production runs on the user's Mac**, NOT on Cloudflare Workers, despite `worker.js` + `wrangler.toml` existing in the tree.

- `launchctl` job `com.rsa-chat.server` runs `node /Users/albert/Desktop/rsa-chat/server.js` on port 3000
- `launchctl` job `com.rsa-chat.tunnel` runs `cloudflared` per `cloudflared.yml`, exposing `localhost:3000` → `https://ppb1s0n.us.kg`
- The repo at `/Users/albert/Desktop/rsa-chat/` is the live source of truth for both static files (served from `public/`) and `server.js`

**To deploy** (run from anywhere):
```bash
git -C /Users/albert/Desktop/rsa-chat pull
launchctl kickstart -k "gui/$(id -u)/com.rsa-chat.server"
```
Static-file-only changes (HTML/JS in `public/`) take effect on the next page load even without the restart, since `server.js` reads from disk each request.

**Do not** use `npm run deploy` / `wrangler deploy` — the user does not use Cloudflare Workers and has no `workers.dev` subdomain. `worker.js` is kept around but unused; treat it as a parallel implementation only relevant if the project ever switches deploy modes.

## Commands

```bash
npm install                  # install deps (ws + wrangler — wrangler unused)
node server.js               # local dev (port 3000)
cd cli && go build -o tacenda-cli .
./tacenda-cli --keygen --out ~/.tacenda/identity.pem
```

## Architecture

No framework, no database, no persistent storage. Three components share one wire protocol.

### Server (`server.js`)

~100-line Node.js WebSocket server. In-memory `Map<sessionPubKeyB64, WebSocket>` is the entire state.

**Protocol — three message types:**
- `{ type: "register", publicKey }` — client announces its session pubkey as its routing address
- `{ type: "message", to, payload, senderKey }` — server routes to the `to` socket; `payload` is an opaque Double Ratchet header (see below). Server never reads `payload`.
- `{ type: "handshake_broadcast", payload, senderSession }` — broadcast to all other sockets; used by CLI for ECIES-style handshake (web client doesn't initiate handshakes — recipients paste session pubkeys directly).

`worker.js` mirrors the same protocol on Cloudflare Durable Objects but is not the active deployment.

### Pages

- `public/index.html` — landing page
- `public/chat.html` — chat UI; all JS inline, no dependencies
- `public/keygen.html` — long-term identity key generator

### Cryptography (current)

**Replaced RSA-OAEP with X25519 + Double Ratchet** (Signal-style). Both `public/chat.html` and `cli/main.go` implement the same protocol.

- **Session keys**: ephemeral X25519, generated on page load / CLI start
- **Long-term identity keys**: X25519, exported as PKCS#8 PEM (RFC 8410). Only the CLI uses these (for receiving broadcast handshakes); the web client only has session keys
- **Initial DH**: `rk_0 = HKDF(DH(my_session_priv, peer_session_pub), info="Tacenda/init/v1")`
- **Per-message ratchet**: each send advances an HMAC-SHA256 chain key → derives `(message_key, mac_key)` via HKDF
- **DH ratchet**: when peer rotates DH pubkey, advance root key via HKDF over fresh DH output; rotate own DH for reply
- **AEAD**: AES-GCM-128 for message body; HMAC-SHA256 over the header. The separate MAC is what gets published on burn (Phase 4, not yet implemented)
- **Handshake (CLI only)**: ECIES sealed-box — ephemeral X25519 + HKDF → AES-GCM encrypts sender's session pubkey to recipient's long-term pubkey

**Wire format for `payload` in `message`:**
```js
{
  dh: <b64 32B sender ratchet pub>,
  pn: <int previous chain length>,
  n:  <int message number in current chain>,
  iv: <b64 12B AES-GCM nonce>,
  ct: <b64 AES-GCM ciphertext>,
  mac: <b64 HMAC over {dh,pn,n,iv,ct} JSON>
}
```

HMAC is computed over the **exact JSON bytes** of `{dh,pn,n,iv,ct}` in that field order — `cli/main.go`'s `canonicalHeaderJSON` must produce identical bytes to JS's `JSON.stringify({dh, pn, n, iv, ct})`.

**Wire format for `payload` in `handshake_broadcast`:**
```js
{ eph: <b64 32B ephemeral X25519 pub>, iv: <b64 12B>, ct: <b64 AES-GCM(sender's session pub)> }
```

### Phase 1 → Phase 4 plan

The crypto migration above is **Phase 1** of a larger redesign documented in `/Users/albert/.claude/plans/pull-snoopy-rose.md`. Upcoming:
- **Phase 2**: drop the `to` field; trial-decrypt all incoming messages
- **Phase 3**: constant-rate equal-size slot scheduler (anonymous broadcast room)
- **Phase 4**: burn UI — publish past MAC keys to enable deniable transcripts

## Code conventions observed in this repo

- Inline JS in HTML, no build step, no framework
- Server-side: zero dependencies beyond `ws` (and `gorilla/websocket` + `golang.org/x/crypto` in CLI)
- Comments only where the *why* is non-obvious — no docstrings, no narration of *what* the code does
- Dark theme, mono font, green/blue accents
