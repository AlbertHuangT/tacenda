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

No framework, no database, no persistent storage. The project has gone through four phases of redesign; the current code is the final Phase 4 state.

### Server (`server.js`, ~50 lines)

Anonymous broadcast room. Every WebSocket frame must be exactly **1024 bytes of binary**; anything else is dropped. The server has no per-client state, no routing table, no JSON parsing — it just length-validates and fans out to all other connected sockets. `worker.js` mirrors the same logic on a Cloudflare Durable Object (parallel implementation, not the active deployment).

### Pages

- `public/index.html` — landing page
- `public/chat.html` — chat UI; all JS inline, no dependencies
- `public/keygen.html` — long-term identity key generator

### Cryptography

X25519 + HKDF-SHA256 + AES-GCM-128 + HMAC-SHA256. Double Ratchet (Signal-style) for chat, ECIES sealed-box for handshakes. Both `public/chat.html` and `cli/main.go` implement byte-identical protocols.

- **Session keys**: ephemeral X25519, generated on page load / CLI start. Destroyed on disconnect.
- **Long-term identity keys** (CLI only): X25519, PKCS#8 PEM. Web has no identity layer; users paste session pubkeys directly.
- **Initial DH**: `rk_0 = HKDF(DH(my_session_priv, peer_session_pub), info="Tacenda/init/v1")`
- **Chain advance**: `nextCK = HMAC(CK, 0x02); mkSeed = HMAC(CK, 0x01); (mk, macKey) = HKDF(mkSeed, "Tacenda/mk-mac/v1", 64)`
- **DH ratchet**: when peer's DH pub changes, advance root key via HKDF over fresh DH output; rotate own DH for next send.
- **Encryption**: AES-GCM-128 keyed by `mk`. **Authentication**: separate HMAC-SHA256 keyed by `macKey` over `[pub || iv || ct]`. The HMAC is structurally redundant given AES-GCM's auth tag, but the separate `macKey` is what gets published on burn (forgery-by-design, while `mk` stays private so old ciphertexts can't be retroactively decrypted).

### Wire protocol (binary slots)

Every WS frame is exactly **1024 bytes**:

```
[0..32]   pub   — X25519 32B (ratchet sender's current DH pub, or ECIES ephemeral pub)
[32..44]  iv    — AES-GCM 12B nonce
[44..76]  mac   — HMAC-SHA256 (ratchet) or random bytes (handshake / noise)
[76..1024] ct   — AES-GCM(plaintext_932B) = 932B + 16B tag = 948B
```

After AES-GCM authenticates and decrypts the 948B payload, the resulting **932B plaintext** has:
```
[0..2]   msg_len   uint16 BE
[2..6]   pn        uint32 BE  (ratchet only; 0 for handshake)
[6..10]  n         uint32 BE  (ratchet only; 0 for handshake)
[10..10+msg_len]  msg
[10+msg_len..932] random padding
```

For ratchet slots, `msg` carries a **type byte + payload**:
- `0x01` (chat) — followed by UTF-8 text
- `0x02` (burn) — followed by `[count uint16 BE]` then `count × (seq uint16 BE, macKey 32B)`

For ECIES (handshake) slots, `msg` is a fixed 33 bytes: `[intent byte: 0x00 init or 0x01 reply] || [sender's session pub 32B]`.

### Slot scheduler

Each client emits exactly one slot every **2 seconds**, whether anything is queued or not. Empty ticks are filled with 1024 random bytes — cryptographically indistinguishable from real ciphertext to the server and any network observer. Real messages and handshakes are queued and drained on tick.

### Trial-decrypt (receive path)

Each incoming slot is tried as ECIES first (against `session_priv`, then `identity_priv` on CLI), then as a ratchet receive against every active contact's ratchet. Ratchet attempts snapshot the ratchet state before trying and restore on any failure (MAC mismatch, AES-GCM auth fail, parse error) so that wrong-peer slots cannot corrupt a chain. Slots that match nothing are silently dropped — this is the normal case for the bulk of broadcast traffic.

### Handshake (2-step ECIES)

`/find <peer_pub>` on CLI or "set" in web sends an **init** handshake slot to whatever pubkey was provided (CLI identity_pub or web session_pub). The peer trial-decrypts with their available private keys; on success they send a **reply** handshake slot back encrypted to the sender's session_pub (extracted from init's plaintext). After both sides have each other's session pubs, ratchets bootstrap as initiator (the one who sent init) or responder.

Simultaneous initiation is broken in chat.html by a pubkey-lex tie-break; CLI doesn't tie-break and the user retries `/find` if both sides happened to initiate at once.

### Burn (Phase 4)

User triggers burn (chat.html "burn" button, CLI `/burn`). The client encodes its accumulated `macKey`s (up to the most recent 27, fitting in one slot's plaintext budget) into a `msgTypeBurn` ratchet slot. The peer's client recognises the type byte and stores the keys to `PeerBurnedMACs`; both sides become read-only. Either side can then export a JSON manifest combining its own `BurnedMACs` and the peer's. With the manifest, anyone can forge fake messages that HMAC-validate against the chain — the transcript loses evidentiary value.

What's published vs. kept private on burn:
- **Published**: only `macKey` per past sent message
- **NOT published**: any DH private key, message key (`mk`), root key, or chain key. Past ciphertexts captured by an eavesdropper stay confidential (forward secrecy preserved).

The burn message itself is sent over the ratchet (so the server can't read it), and consumes one more chain step like any chat message. The burn's own `macKey` is included in the published set (the last entry, since the burn pushes to `BurnedMACs` before it's sent).

## Code conventions

- Inline JS in HTML, no build step, no framework
- Server-side: zero dependencies beyond `ws` (and `gorilla/websocket` + `golang.org/x/crypto` in CLI)
- Comments only where the *why* is non-obvious — no docstrings, no narration of *what* the code does
- Dark theme, mono font, green/blue accents (red for burn button)

## Past phases (already shipped, listed for archeology)

| Phase | What landed | Wire delta |
|---|---|---|
| 1 | X25519 + Double Ratchet replaced RSA-OAEP | Same JSON envelope; payload shape changes (`{dh,pn,n,iv,ct,mac}`) |
| 2 | Drop `to` / `senderKey` / `register`; trial-decrypt | Server becomes pure broadcaster; all routing client-side |
| 3 | Constant-rate 1024B binary slot, random-noise filler | JSON envelope gone entirely; wire is fixed-size binary |
| 4 | Burn: inner type byte + macKey publishing + manifest export | Inner plaintext now starts with a type byte (chat / burn) |

Detailed phase rationale lives in `/Users/albert/.claude/plans/pull-snoopy-rose.md`.
