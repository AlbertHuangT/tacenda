package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/hkdf"
)

// ── Wire types ────────────────────────────────────────────────────────────────

// Header is the Double-Ratchet message header used in {type:"message"} payloads.
// Field order matters: HMAC is computed over its canonical JSON encoding, which
// must match the JS client's JSON.stringify output exactly.
type Header struct {
	DH  string `json:"dh"`
	PN  int    `json:"pn"`
	N   int    `json:"n"`
	IV  string `json:"iv"`
	CT  string `json:"ct"`
	MAC string `json:"mac,omitempty"`
}

// HandshakePayload is the ECIES envelope inside a handshake_broadcast.
type HandshakePayload struct {
	Eph string `json:"eph"` // base64 ephemeral X25519 pubkey (32B)
	IV  string `json:"iv"`  // base64 12B AES-GCM nonce
	CT  string `json:"ct"`  // base64 AES-GCM(plaintext = sender session pub 32B)
}

type IncomingMessage struct {
	Type    string          `json:"type"`
	Payload json.RawMessage `json:"payload"`
}

// ── Ratchet state ────────────────────────────────────────────────────────────

const (
	rkInfo   = "Tacenda/rk/v1"
	mkInfo   = "Tacenda/mk-mac/v1"
	initInfo = "Tacenda/init/v1"
	hsInfo   = "Tacenda/handshake/v1"
)

type Ratchet struct {
	DHs       *ecdh.PrivateKey // my current DH keypair
	DHsPubRaw []byte           // 32B
	DHrRaw    []byte           // peer's last DH pubkey (32B)
	RK        []byte           // root key (32B)
	CKs       []byte           // sending chain key, nil until first send-bootstrap
	CKr       []byte           // receiving chain key
	Ns        int
	Nr        int
	PN        int

	// MAC keys we've produced for sent messages; published on burn.
	BurnedMACs []BurnedMAC
}

type BurnedMAC struct {
	Seq    int    `json:"seq"`
	MacKey string `json:"macKey"` // base64
}

// Contact holds a peer's identity and current ratchet state.
type Contact struct {
	ID            int
	SessionKeyB64 string // peer's session pub (base64)
	SessionPubRaw []byte // 32B
	R             *Ratchet
}

// ── Global state ─────────────────────────────────────────────────────────────

var (
	identityPriv *ecdh.PrivateKey // long-term X25519 identity (optional)
	identityPub  []byte

	sessionPriv      *ecdh.PrivateKey // per-process X25519 session keypair
	sessionPubRaw   []byte
	sessionPubB64   string

	contacts      = map[int]*Contact{}
	contactsMu    sync.Mutex
	nextContactID = 1
	activeContact *Contact

	conn   *websocket.Conn
	connMu sync.Mutex
)

// ── Main ─────────────────────────────────────────────────────────────────────

func main() {
	keygenMode := flag.Bool("keygen", false, "generate a new long-term X25519 identity key pair and exit")
	keyOut := flag.String("out", "identity.pem", "output path for --keygen (private key)")
	keyPath := flag.String("key", "", "path to identity private key PEM file")
	server := flag.String("server", "ws://localhost:3000/ws", "WebSocket server URL")
	flag.Parse()

	if *keygenMode {
		runKeygen(*keyOut)
		return
	}

	if *keyPath == "" {
		home, _ := os.UserHomeDir()
		def := filepath.Join(home, ".tacenda", "identity.pem")
		if _, err := os.Stat(def); err == nil {
			*keyPath = def
		}
	}

	if *keyPath != "" {
		var err error
		identityPriv, err = loadX25519PrivPEM(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading key %s: %v\n", *keyPath, err)
			os.Exit(1)
		}
		identityPub = identityPriv.PublicKey().Bytes()
		fmt.Println("identity  :", truncate(base64.StdEncoding.EncodeToString(identityPub), 48))
	} else {
		fmt.Println("no identity key loaded — handshake receive disabled (use --key or --keygen)")
	}

	// Fresh session keypair each run
	curve := ecdh.X25519()
	var err error
	sessionPriv, err = curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to generate session key:", err)
		os.Exit(1)
	}
	sessionPubRaw = sessionPriv.PublicKey().Bytes()
	sessionPubB64 = base64.StdEncoding.EncodeToString(sessionPubRaw)
	fmt.Println("session   :", truncate(sessionPubB64, 48))

	c, _, err := websocket.DefaultDialer.Dial(*server, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connection failed:", err)
		os.Exit(1)
	}
	conn = c
	defer conn.Close()

	// Phase 2: no `register` — server is a pure broadcaster. Other clients learn
	// our session_pub via the handshake protocol (ECIES sealed-box).
	fmt.Println("connected :", *server)
	printHelp()

	go readLoop()
	inputLoop()
}

// ── Keygen ───────────────────────────────────────────────────────────────────

func runKeygen(outPath string) {
	fmt.Println("generating X25519 key pair…")
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintln(os.Stderr, "key generation failed:", err)
		os.Exit(1)
	}

	// PKCS#8 PEM (RFC 8410 for X25519) — compatible with Web Crypto exportKey("pkcs8")
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal failed:", err)
		os.Exit(1)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	if d := filepath.Dir(outPath); d != "." {
		if err := os.MkdirAll(d, 0700); err != nil {
			fmt.Fprintln(os.Stderr, "mkdir failed:", err)
			os.Exit(1)
		}
	}
	if err := os.WriteFile(outPath, privPEM, 0600); err != nil {
		fmt.Fprintln(os.Stderr, "write failed:", err)
		os.Exit(1)
	}

	pubB64 := base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes())
	fmt.Println()
	fmt.Println("private key saved to:", outPath)
	fmt.Println()
	fmt.Println("your long-term public key — share this with friends (once, offline):")
	fmt.Println()
	fmt.Println(pubB64)
	fmt.Println()
	fmt.Println("keep identity.pem safe. anyone who obtains it can impersonate you.")
}

func loadX25519PrivPEM(path string) (*ecdh.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParsePKCS8PrivateKey: %w", err)
	}
	ecPriv, ok := keyIface.(*ecdh.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an ECDH key (got %T) — expected X25519", keyIface)
	}
	if ecPriv.Curve() != ecdh.X25519() {
		return nil, fmt.Errorf("ECDH curve is not X25519")
	}
	return ecPriv, nil
}

// ── Crypto primitives ────────────────────────────────────────────────────────

func dhX25519(priv *ecdh.PrivateKey, peerPubRaw []byte) ([]byte, error) {
	peerPub, err := ecdh.X25519().NewPublicKey(peerPubRaw)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(peerPub)
}

func hkdfDerive(ikm, salt []byte, info string, length int) ([]byte, error) {
	r := hkdf.New(sha256.New, ikm, salt, []byte(info))
	out := make([]byte, length)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func hmacSHA256(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func aesGCMEnc(key, iv, pt, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, iv, pt, aad), nil
}

func aesGCMDec(key, iv, ct, aad []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, ct, aad)
}

// ── Double Ratchet ──────────────────────────────────────────────────────────

func ratchetInit(amInitiator bool, mySessionKP *ecdh.PrivateKey, peerSessionPubRaw []byte) (*Ratchet, error) {
	shared, err := dhX25519(mySessionKP, peerSessionPubRaw)
	if err != nil {
		return nil, err
	}
	rk0, err := hkdfDerive(shared, make([]byte, 32), initInfo, 32)
	if err != nil {
		return nil, err
	}
	r := &Ratchet{
		DHs:       mySessionKP,
		DHsPubRaw: mySessionKP.PublicKey().Bytes(),
		DHrRaw:    append([]byte{}, peerSessionPubRaw...),
		RK:        rk0,
	}
	if amInitiator {
		fresh, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		r.DHs = fresh
		r.DHsPubRaw = fresh.PublicKey().Bytes()
		dhOut, err := dhX25519(r.DHs, r.DHrRaw)
		if err != nil {
			return nil, err
		}
		out, err := hkdfDerive(dhOut, r.RK, rkInfo, 64)
		if err != nil {
			return nil, err
		}
		r.RK = out[:32]
		r.CKs = out[32:]
	}
	return r, nil
}

// advanceCK returns next chain key, message key, and mac key.
func advanceCK(ck []byte) (nextCK, mk, macKey []byte, err error) {
	mkSeed := hmacSHA256(ck, []byte{0x01})
	nextCK = hmacSHA256(ck, []byte{0x02})
	out, err := hkdfDerive(mkSeed, make([]byte, 32), mkInfo, 64)
	if err != nil {
		return nil, nil, nil, err
	}
	return nextCK, out[:32], out[32:], nil
}

func dhRatchetSending(r *Ratchet) error {
	dhOut, err := dhX25519(r.DHs, r.DHrRaw)
	if err != nil {
		return err
	}
	out, err := hkdfDerive(dhOut, r.RK, rkInfo, 64)
	if err != nil {
		return err
	}
	r.RK = out[:32]
	r.CKs = out[32:]
	r.PN = r.Ns
	r.Ns = 0
	return nil
}

func dhRatchetReceiving(r *Ratchet, newDHrRaw []byte) error {
	r.DHrRaw = append([]byte{}, newDHrRaw...)
	dhOut, err := dhX25519(r.DHs, r.DHrRaw)
	if err != nil {
		return err
	}
	out, err := hkdfDerive(dhOut, r.RK, rkInfo, 64)
	if err != nil {
		return err
	}
	r.RK = out[:32]
	r.CKr = out[32:]
	r.Nr = 0
	// Rotate own DHs for next send
	fresh, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	r.DHs = fresh
	r.DHsPubRaw = fresh.PublicKey().Bytes()
	return dhRatchetSending(r)
}

func ratchetEncrypt(r *Ratchet, plaintext []byte) (*Header, error) {
	if r.CKs == nil {
		return nil, fmt.Errorf("no sending chain (responder must wait for first incoming message)")
	}
	nextCK, mk, macKey, err := advanceCK(r.CKs)
	if err != nil {
		return nil, err
	}
	r.CKs = nextCK
	seq := r.Ns
	r.Ns++
	r.BurnedMACs = append(r.BurnedMACs, BurnedMAC{
		Seq:    seq,
		MacKey: base64.StdEncoding.EncodeToString(macKey),
	})

	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct, err := aesGCMEnc(mk, iv, plaintext, nil)
	if err != nil {
		return nil, err
	}

	h := &Header{
		DH: base64.StdEncoding.EncodeToString(r.DHsPubRaw),
		PN: r.PN,
		N:  seq,
		IV: base64.StdEncoding.EncodeToString(iv),
		CT: base64.StdEncoding.EncodeToString(ct),
	}
	macInput, err := canonicalHeaderJSON(h)
	if err != nil {
		return nil, err
	}
	mac := hmacSHA256(macKey, macInput)
	h.MAC = base64.StdEncoding.EncodeToString(mac)
	return h, nil
}

func ratchetDecrypt(r *Ratchet, h *Header) ([]byte, error) {
	incomingDHr, err := base64.StdEncoding.DecodeString(h.DH)
	if err != nil {
		return nil, err
	}
	if r.DHrRaw == nil || !bytes.Equal(incomingDHr, r.DHrRaw) {
		if err := dhRatchetReceiving(r, incomingDHr); err != nil {
			return nil, err
		}
	}
	if r.CKr == nil {
		return nil, fmt.Errorf("no receiving chain")
	}
	var mk, macKey []byte
	for r.Nr <= h.N {
		next, m, mac, err := advanceCK(r.CKr)
		if err != nil {
			return nil, err
		}
		r.CKr = next
		mk = m
		macKey = mac
		r.Nr++
		if r.Nr-1 == h.N {
			break
		}
	}
	if r.Nr-1 != h.N {
		return nil, fmt.Errorf("ratchet desync")
	}
	hc := *h
	hc.MAC = ""
	macInput, err := canonicalHeaderJSON(&hc)
	if err != nil {
		return nil, err
	}
	expected := hmacSHA256(macKey, macInput)
	gotMac, err := base64.StdEncoding.DecodeString(h.MAC)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(expected, gotMac) {
		return nil, fmt.Errorf("mac mismatch")
	}
	iv, err := base64.StdEncoding.DecodeString(h.IV)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(h.CT)
	if err != nil {
		return nil, err
	}
	return aesGCMDec(mk, iv, ct, nil)
}

// canonicalHeaderJSON produces the exact bytes that JS's
// JSON.stringify({dh, pn, n, iv, ct}) produces, so HMAC is interoperable.
func canonicalHeaderJSON(h *Header) ([]byte, error) {
	// Match JS field order and lack of whitespace; integers without decimals;
	// base64 strings contain no characters that need escaping beyond '+/=' which
	// JSON treats literally. Use json.Marshal on a struct with explicit order.
	type canon struct {
		DH string `json:"dh"`
		PN int    `json:"pn"`
		N  int    `json:"n"`
		IV string `json:"iv"`
		CT string `json:"ct"`
	}
	return json.Marshal(canon{DH: h.DH, PN: h.PN, N: h.N, IV: h.IV, CT: h.CT})
}

// ── Handshake (ECIES sealed-box, mutual 2-step) ─────────────────────────────
//
// Plaintext format (33 bytes after AES-GCM decrypt):
//   byte[0]     = intent  (0x00 = init / 0x01 = reply)
//   byte[1..33] = sender's session pubkey (32B raw)
//
// Flow:
//   /find <pub>      → send init handshake (encrypted to <pub>)
//   recv init        → send reply + bootstrap ratchet as responder
//   recv reply       → bootstrap ratchet as initiator (we initiated)

func ecesEncrypt(recipientPubRaw, plaintext []byte) (*HandshakePayload, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	dhOut, err := dhX25519(eph, recipientPubRaw)
	if err != nil {
		return nil, err
	}
	key, err := hkdfDerive(dhOut, make([]byte, 32), hsInfo, 32)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct, err := aesGCMEnc(key, iv, plaintext, nil)
	if err != nil {
		return nil, err
	}
	return &HandshakePayload{
		Eph: base64.StdEncoding.EncodeToString(eph.PublicKey().Bytes()),
		IV:  base64.StdEncoding.EncodeToString(iv),
		CT:  base64.StdEncoding.EncodeToString(ct),
	}, nil
}

func ecesDecrypt(privKey *ecdh.PrivateKey, p *HandshakePayload) ([]byte, error) {
	ephRaw, err := base64.StdEncoding.DecodeString(p.Eph)
	if err != nil {
		return nil, err
	}
	iv, err := base64.StdEncoding.DecodeString(p.IV)
	if err != nil {
		return nil, err
	}
	ct, err := base64.StdEncoding.DecodeString(p.CT)
	if err != nil {
		return nil, err
	}
	dhOut, err := dhX25519(privKey, ephRaw)
	if err != nil {
		return nil, err
	}
	key, err := hkdfDerive(dhOut, make([]byte, 32), hsInfo, 32)
	if err != nil {
		return nil, err
	}
	return aesGCMDec(key, iv, ct, nil)
}

func broadcastHandshake(peerPubB64 string) error {
	peerPubRaw, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(peerPubRaw) != 32 {
		return fmt.Errorf("pubkey must be 32 bytes (got %d)", len(peerPubRaw))
	}
	plaintext := append([]byte{0x00}, sessionPubRaw...) // init
	payload, err := ecesEncrypt(peerPubRaw, plaintext)
	if err != nil {
		return err
	}
	return sendJSON(map[string]any{
		"type":    "handshake_broadcast",
		"payload": payload,
	})
}

func handleHandshake(msg IncomingMessage) {
	var p HandshakePayload
	if err := json.Unmarshal(msg.Payload, &p); err != nil {
		return
	}

	// Try to decrypt with session_priv first; if that fails, try identity_priv.
	// Session-keyed handshakes arrive when a peer is replying (they learned our
	// session pub via our own outgoing handshake) or initiating to our session
	// pub (e.g. from a web client we shared session pub with). Identity-keyed
	// handshakes arrive when a peer initiated with our out-of-band identity pub.
	var plaintext []byte
	var err error
	plaintext, err = ecesDecrypt(sessionPriv, &p)
	if err != nil && identityPriv != nil {
		plaintext, err = ecesDecrypt(identityPriv, &p)
	}
	if err != nil {
		return // not for us
	}
	if len(plaintext) != 33 {
		return
	}

	intent := plaintext[0]
	senderPub := plaintext[1:33]
	senderPubB64 := base64.StdEncoding.EncodeToString(senderPub)

	contactsMu.Lock()
	// De-dupe: if we already have a contact for this peer session_pub, reuse it
	var c *Contact
	for _, k := range contacts {
		if k.SessionKeyB64 == senderPubB64 {
			c = k
			break
		}
	}
	if c == nil {
		id := nextContactID
		nextContactID++
		c = &Contact{ID: id, SessionKeyB64: senderPubB64, SessionPubRaw: append([]byte{}, senderPub...)}
		contacts[id] = c
	}
	if c.R != nil {
		contactsMu.Unlock()
		return // already bootstrapped; ignore duplicate handshake
	}
	contactsMu.Unlock()

	switch intent {
	case 0x00: // init — peer is reaching out. Reply and bootstrap as responder.
		reply := append([]byte{0x01}, sessionPubRaw...)
		replyPayload, err := ecesEncrypt(senderPub, reply)
		if err != nil {
			printLine("[⚠ handshake reply failed: " + err.Error() + "]")
			return
		}
		_ = sendJSON(map[string]any{"type": "handshake_broadcast", "payload": replyPayload})

		r, err := ratchetInit(false, sessionPriv, senderPub)
		if err != nil {
			printLine("[⚠ ratchet init failed: " + err.Error() + "]")
			return
		}
		contactsMu.Lock()
		c.R = r
		activeContact = c
		contactsMu.Unlock()
		printLine(fmt.Sprintf("[!] incoming handshake → contact #%d (now active)", c.ID))

	case 0x01: // reply — we initiated. Bootstrap as initiator.
		r, err := ratchetInit(true, sessionPriv, senderPub)
		if err != nil {
			printLine("[⚠ ratchet init failed: " + err.Error() + "]")
			return
		}
		contactsMu.Lock()
		c.R = r
		activeContact = c
		contactsMu.Unlock()
		printLine(fmt.Sprintf("[✓] handshake complete → contact #%d (now active)", c.ID))
	}
}

// ── Message handler — trial-decrypt against every contact's ratchet ─────────

func handleMessage(msg IncomingMessage) {
	var h Header
	if err := json.Unmarshal(msg.Payload, &h); err != nil {
		return
	}
	contactsMu.Lock()
	candidates := make([]*Contact, 0, len(contacts))
	for _, c := range contacts {
		if c.R != nil {
			candidates = append(candidates, c)
		}
	}
	contactsMu.Unlock()

	for _, c := range candidates {
		// ratchetDecrypt mutates c.R; on failure, the ratchet state isn't
		// committed because dhRatchetReceiving runs only if DHr changes, and
		// the chain key advance happens inside the loop after MAC verification.
		// To avoid corrupting a ratchet on a wrong-peer attempt, we snapshot
		// and restore on failure.
		snapshot := *c.R
		snapBurned := append([]BurnedMAC(nil), c.R.BurnedMACs...)
		pt, err := ratchetDecrypt(c.R, &h)
		if err == nil {
			ts := time.Now().Format("15:04")
			printLine(fmt.Sprintf("[%s] [#%d] %s", ts, c.ID, string(pt)))
			return
		}
		*c.R = snapshot
		c.R.BurnedMACs = snapBurned
	}
	// All contacts failed → silently drop (message wasn't for us)
}

func sendChatMessage(text string) {
	if activeContact == nil {
		fmt.Println("[no active contact — /find <pub> first]")
		return
	}
	if activeContact.R == nil {
		fmt.Println("[handshake not complete yet — wait for the peer to come online]")
		return
	}
	h, err := ratchetEncrypt(activeContact.R, []byte(text))
	if err != nil {
		fmt.Println("[⚠ encrypt failed:", err, "]")
		return
	}
	sendJSON(map[string]any{
		"type":    "message",
		"payload": h,
	})
	ts := time.Now().Format("15:04")
	fmt.Printf("[%s] [me→#%d] %s\n", ts, activeContact.ID, text)
}

// ── WebSocket I/O ───────────────────────────────────────────────────────────

func readLoop() {
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("\n[disconnected]")
			os.Exit(0)
		}
		var msg IncomingMessage
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}
		switch msg.Type {
		case "handshake_broadcast":
			handleHandshake(msg)
		case "message":
			handleMessage(msg)
		}
	}
}

func inputLoop() {
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "/") {
			handleCommand(line)
		} else {
			sendChatMessage(line)
		}
	}
}

func handleCommand(line string) {
	parts := strings.Fields(line)
	switch parts[0] {
	case "/find":
		if len(parts) < 2 {
			fmt.Println("usage: /find <friend_long_term_public_key_base64>")
			return
		}
		if err := broadcastHandshake(parts[1]); err != nil {
			fmt.Println("[⚠ handshake failed:", err, "]")
		} else {
			fmt.Println("[handshake broadcast sent — waiting for friend to respond]")
		}
	case "/chat":
		if len(parts) < 2 {
			fmt.Println("usage: /chat <contact_id>")
			return
		}
		var id int
		fmt.Sscan(parts[1], &id)
		contactsMu.Lock()
		c, ok := contacts[id]
		if ok {
			activeContact = c
		}
		contactsMu.Unlock()
		if ok {
			fmt.Printf("[active contact: #%d  %s…]\n", id, truncate(c.SessionKeyB64, 24))
		} else {
			fmt.Println("[contact not found]")
		}
	case "/contacts":
		contactsMu.Lock()
		if len(contacts) == 0 {
			fmt.Println("[no contacts yet]")
		} else {
			for _, c := range contacts {
				mark := "  "
				if activeContact != nil && activeContact.ID == c.ID {
					mark = "* "
				}
				fmt.Printf("  %s#%d  %s…\n", mark, c.ID, truncate(c.SessionKeyB64, 32))
			}
		}
		contactsMu.Unlock()
	case "/mykey":
		fmt.Println(sessionPubB64)
	case "/help":
		printHelp()
	case "/quit":
		fmt.Println("[goodbye]")
		conn.Close()
		os.Exit(0)
	default:
		fmt.Println("[unknown command — /help for list]")
	}
}

// ── Utilities ───────────────────────────────────────────────────────────────

func sendJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	connMu.Lock()
	defer connMu.Unlock()
	return conn.WriteMessage(websocket.TextMessage, data)
}

func printLine(s string) { fmt.Printf("\r%s\n> ", s) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func printHelp() {
	fmt.Println(`
commands:
  /find <pubkey>              start a chat — broadcasts a sealed handshake to <pubkey>
                              (identity pub for CLI peers, session pub for web peers)
  /chat <n>                   switch active contact
  /contacts                   list all known contacts (* = active)
  /mykey                      print your current session public key
  /help                       show this help
  /quit                       exit
  <anything else>             send encrypted message to active contact

incoming handshakes set the new contact as active automatically; reply by typing.`)
}
