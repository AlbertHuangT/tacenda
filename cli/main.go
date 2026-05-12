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
	"encoding/binary"
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

// ── Slot wire format (Phase 3) ────────────────────────────────────────────────
//
// Every WebSocket frame is exactly slotSize bytes of binary. Layout:
//   [0..32]    pub   — X25519 32B (ratchet DH pub or ECIES ephemeral pub)
//   [32..44]   iv    — AES-GCM 12B nonce
//   [44..76]   mac   — HMAC-SHA256 (ratchet) or random (handshake/noise)
//   [76..1024] ct    — AES-GCM(932B plaintext) → 932 + 16B tag = 948B
//
// Plaintext (932B after auth):
//   [0..2]   msg_len  uint16 BE
//   [2..6]   pn       uint32 BE
//   [6..10]  n        uint32 BE
//   [10..10+msg_len]  msg
//   [10+msg_len..932] random padding

const (
	slotSize        = 1024
	slotPubOffset   = 0
	slotIVOffset    = 32
	slotMACOffset   = 44
	slotCTOffset    = 76
	slotCTSize      = slotSize - slotCTOffset // 948
	slotPTSize      = slotCTSize - 16          // 932 (AES-GCM tag is 16B)
	slotMetaSize    = 10                       // 2 + 4 + 4
	maxMsgLen       = slotPTSize - slotMetaSize // 922
	slotIntervalMs  = 2000

	// Inner message-type byte (Phase 4 wire format)
	msgTypeChat = 0x01
	msgTypeBurn = 0x02

	burnEntrySize    = 34
	maxBurnEntries   = (maxMsgLen - 3) / burnEntrySize // 27
)

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
	ID             int
	SessionKeyB64  string // peer's session pub (base64)
	SessionPubRaw  []byte // 32B
	R              *Ratchet
	Burned         bool       // conversation burned (sent or received); no more sends
	PeerBurnedMACs []BurnedMAC // mac keys peer published in their burn message
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

	// Phase 3: server is a pure 1024-byte slot broadcaster. We emit one slot
	// every slotInterval (real ciphertext if queued, random noise otherwise).
	fmt.Printf("connected : %s  (slot=%dB every %dms)\n", *server, slotSize, slotIntervalMs)
	printHelp()

	go readLoop()
	go slotScheduler()
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

// packPlaintext fills a 932-byte plaintext block: meta(10B) + msg + random pad.
func packPlaintext(msg []byte, pn, n uint32) ([]byte, error) {
	if len(msg) > maxMsgLen {
		return nil, fmt.Errorf("message too long for one slot (%d > %d)", len(msg), maxMsgLen)
	}
	pt := make([]byte, slotPTSize)
	if _, err := rand.Read(pt); err != nil {
		return nil, err
	}
	binary.BigEndian.PutUint16(pt[0:2], uint16(len(msg)))
	binary.BigEndian.PutUint32(pt[2:6], pn)
	binary.BigEndian.PutUint32(pt[6:10], n)
	copy(pt[slotMetaSize:], msg)
	return pt, nil
}

func unpackPlaintext(pt []byte) (msg []byte, pn, n uint32, err error) {
	if len(pt) != slotPTSize {
		return nil, 0, 0, fmt.Errorf("bad plaintext size %d", len(pt))
	}
	ml := binary.BigEndian.Uint16(pt[0:2])
	if int(ml) > maxMsgLen {
		return nil, 0, 0, fmt.Errorf("declared msg_len %d exceeds budget", ml)
	}
	pn = binary.BigEndian.Uint32(pt[2:6])
	n = binary.BigEndian.Uint32(pt[6:10])
	msg = pt[slotMetaSize : slotMetaSize+int(ml)]
	return msg, pn, n, nil
}

// encodeRatchetSlot consumes one chain-key step on the sending side and
// produces a 1024-byte slot. Mutates r.CKs / r.Ns / r.BurnedMACs.
func encodeRatchetSlot(r *Ratchet, msg []byte) ([]byte, error) {
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
	r.BurnedMACs = append(r.BurnedMACs, BurnedMAC{Seq: seq, MacKey: base64.StdEncoding.EncodeToString(macKey)})

	pt, err := packPlaintext(msg, uint32(r.PN), uint32(seq))
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct, err := aesGCMEnc(mk, iv, pt, nil)
	if err != nil {
		return nil, err
	}

	slot := make([]byte, slotSize)
	copy(slot[slotPubOffset:slotPubOffset+32], r.DHsPubRaw)
	copy(slot[slotIVOffset:slotIVOffset+12], iv)
	copy(slot[slotCTOffset:], ct)

	macInput := make([]byte, 0, 32+12+slotCTSize)
	macInput = append(macInput, slot[slotPubOffset:slotPubOffset+32]...)
	macInput = append(macInput, slot[slotIVOffset:slotIVOffset+12]...)
	macInput = append(macInput, slot[slotCTOffset:]...)
	mac := hmacSHA256(macKey, macInput)
	copy(slot[slotMACOffset:slotMACOffset+32], mac)
	return slot, nil
}

// encodeHandshakeSlot produces an ECIES sealed-box slot. The mac field is
// random so the slot is indistinguishable from a ratchet slot on the wire.
func encodeHandshakeSlot(recipientPubRaw, msg []byte) ([]byte, error) {
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
	pt, err := packPlaintext(msg, 0, 0)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	ct, err := aesGCMEnc(key, iv, pt, nil)
	if err != nil {
		return nil, err
	}
	slot := make([]byte, slotSize)
	copy(slot[slotPubOffset:slotPubOffset+32], eph.PublicKey().Bytes())
	copy(slot[slotIVOffset:slotIVOffset+12], iv)
	if _, err := rand.Read(slot[slotMACOffset : slotMACOffset+32]); err != nil {
		return nil, err
	}
	copy(slot[slotCTOffset:], ct)
	return slot, nil
}

// tryEciesDecryptSlot returns the inner message bytes if `priv` can decrypt the
// slot's ECIES envelope; otherwise nil. Stateless.
func tryEciesDecryptSlot(priv *ecdh.PrivateKey, slot []byte) []byte {
	pub := slot[slotPubOffset : slotPubOffset+32]
	iv := slot[slotIVOffset : slotIVOffset+12]
	ct := slot[slotCTOffset:]
	dhOut, err := dhX25519(priv, pub)
	if err != nil {
		return nil
	}
	key, err := hkdfDerive(dhOut, make([]byte, 32), hsInfo, 32)
	if err != nil {
		return nil
	}
	pt, err := aesGCMDec(key, iv, ct, nil)
	if err != nil {
		return nil
	}
	msg, _, _, err := unpackPlaintext(pt)
	if err != nil {
		return nil
	}
	return append([]byte{}, msg...)
}

// tryRatchetDecryptSlot snapshots ratchet state, attempts a receive step, and
// commits only on full success (MAC verify + AES-GCM decrypt). Returns the
// message bytes on success, nil otherwise.
func tryRatchetDecryptSlot(r *Ratchet, slot []byte) []byte {
	pub := slot[slotPubOffset : slotPubOffset+32]
	iv := slot[slotIVOffset : slotIVOffset+12]
	mac := slot[slotMACOffset : slotMACOffset+32]
	ct := slot[slotCTOffset:]

	saved := *r
	saved.BurnedMACs = append([]BurnedMAC(nil), r.BurnedMACs...)
	commit := false
	defer func() {
		if !commit {
			*r = saved
		}
	}()

	if r.DHrRaw == nil || !bytes.Equal(pub, r.DHrRaw) {
		if err := dhRatchetReceiving(r, pub); err != nil {
			return nil
		}
	}
	if r.CKr == nil {
		return nil
	}
	nextCK, mk, macKey, err := advanceCK(r.CKr)
	if err != nil {
		return nil
	}
	r.CKr = nextCK
	r.Nr++

	macInput := make([]byte, 0, 32+12+slotCTSize)
	macInput = append(macInput, pub...)
	macInput = append(macInput, iv...)
	macInput = append(macInput, ct...)
	expected := hmacSHA256(macKey, macInput)
	if !hmac.Equal(expected, mac) {
		return nil
	}
	pt, err := aesGCMDec(mk, iv, ct, nil)
	if err != nil {
		return nil
	}
	msg, _, _, err := unpackPlaintext(pt)
	if err != nil {
		return nil
	}
	commit = true
	return append([]byte{}, msg...)
}

// ── Handshake (ECIES sealed-box, mutual 2-step over slot wire format) ───────
//
// Handshake plaintext = 33 bytes:  [intent_byte] || [sender session pub 32B]
//   intent = 0x00 (init) | 0x01 (reply)
//
// Flow:
//   /find <pub>  → enqueue init handshake slot encrypted to <pub>
//   recv init    → enqueue reply slot + bootstrap ratchet as responder
//   recv reply   → bootstrap ratchet as initiator

func broadcastHandshake(peerPubB64 string) error {
	peerPubRaw, err := base64.StdEncoding.DecodeString(peerPubB64)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	if len(peerPubRaw) != 32 {
		return fmt.Errorf("pubkey must be 32 bytes (got %d)", len(peerPubRaw))
	}
	plaintext := append([]byte{0x00}, sessionPubRaw...)
	slot, err := encodeHandshakeSlot(peerPubRaw, plaintext)
	if err != nil {
		return err
	}
	enqueueSlot(slot)
	return nil
}

// handleHandshakePlaintext consumes a decrypted 33-byte handshake payload and
// either replies + bootstraps as responder, or bootstraps as initiator. Called
// after tryEciesDecryptSlot succeeds for an incoming slot.
func handleHandshakePlaintext(plaintext []byte) {
	if len(plaintext) != 33 {
		return
	}
	intent := plaintext[0]
	senderPub := plaintext[1:33]
	senderPubB64 := base64.StdEncoding.EncodeToString(senderPub)

	contactsMu.Lock()
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
		return
	}
	contactsMu.Unlock()

	switch intent {
	case 0x00:
		reply := append([]byte{0x01}, sessionPubRaw...)
		replySlot, err := encodeHandshakeSlot(senderPub, reply)
		if err != nil {
			printLine("[⚠ handshake reply failed: " + err.Error() + "]")
			return
		}
		enqueueSlot(replySlot)
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
	case 0x01:
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

// handleSlot routes an incoming binary slot: trial-decrypt as ECIES (handshake)
// first against session_priv + identity_priv, then as ratchet against every
// active contact. Failures are silent — most slots are noise or not for us.
func handleSlot(slot []byte) {
	if pt := tryEciesDecryptSlot(sessionPriv, slot); pt != nil {
		handleHandshakePlaintext(pt)
		return
	}
	if identityPriv != nil {
		if pt := tryEciesDecryptSlot(identityPriv, slot); pt != nil {
			handleHandshakePlaintext(pt)
			return
		}
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
		if msg := tryRatchetDecryptSlot(c.R, slot); msg != nil {
			dispatchRatchetMessage(c, msg)
			return
		}
	}
	// Not for us — silently drop
}

// Inner type-byte dispatch (Phase 4 wire format).
func dispatchRatchetMessage(c *Contact, bytes []byte) {
	if len(bytes) < 1 {
		return
	}
	ts := time.Now().Format("15:04")
	switch bytes[0] {
	case msgTypeChat:
		printLine(fmt.Sprintf("[%s] [#%d] %s", ts, c.ID, string(bytes[1:])))
	case msgTypeBurn:
		if len(bytes) < 3 {
			return
		}
		count := binary.BigEndian.Uint16(bytes[1:3])
		if int(count) > maxBurnEntries || 3+int(count)*burnEntrySize > len(bytes) {
			return
		}
		entries := make([]BurnedMAC, 0, count)
		for i := 0; i < int(count); i++ {
			off := 3 + i*burnEntrySize
			seq := binary.BigEndian.Uint16(bytes[off : off+2])
			macKey := base64.StdEncoding.EncodeToString(bytes[off+2 : off+2+32])
			entries = append(entries, BurnedMAC{Seq: int(seq), MacKey: macKey})
		}
		contactsMu.Lock()
		c.PeerBurnedMACs = entries
		c.Burned = true
		contactsMu.Unlock()
		printLine(fmt.Sprintf("[🔥 #%d peer burned the conversation — %d mac key(s) received. Transcript now publicly forgeable. Read-only.]", c.ID, count))
	}
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
	if activeContact.Burned {
		fmt.Println("[conversation burned — read-only]")
		return
	}
	inner := append([]byte{msgTypeChat}, []byte(text)...)
	if len(inner) > maxMsgLen {
		fmt.Printf("[message too long: %d > %d bytes per slot — chunking not implemented]\n", len(inner), maxMsgLen-1)
		return
	}
	slot, err := encodeRatchetSlot(activeContact.R, inner)
	if err != nil {
		fmt.Println("[⚠ encrypt failed:", err, "]")
		return
	}
	enqueueSlot(slot)
	ts := time.Now().Format("15:04")
	fmt.Printf("[%s] [me→#%d] %s\n", ts, activeContact.ID, text)
}

// burnConversation publishes recent macKeys of the active contact's outgoing
// chain. The chat is then locked. Local mac keys remain; manifest can be
// exported via /manifest <path>.
func burnConversation() {
	if activeContact == nil {
		fmt.Println("[no active contact]")
		return
	}
	if activeContact.R == nil {
		fmt.Println("[handshake not complete yet]")
		return
	}
	if activeContact.Burned {
		fmt.Println("[already burned]")
		return
	}
	if activeContact.R.CKs == nil || len(activeContact.R.BurnedMACs) == 0 {
		fmt.Println("[no sent messages to burn — send at least one chat message first]")
		return
	}

	all := activeContact.R.BurnedMACs
	start := 0
	if len(all) > maxBurnEntries {
		start = len(all) - maxBurnEntries
	}
	entries := all[start:]

	inner := make([]byte, 3+len(entries)*burnEntrySize)
	inner[0] = msgTypeBurn
	binary.BigEndian.PutUint16(inner[1:3], uint16(len(entries)))
	for i, e := range entries {
		off := 3 + i*burnEntrySize
		binary.BigEndian.PutUint16(inner[off:off+2], uint16(e.Seq))
		macKey, err := base64.StdEncoding.DecodeString(e.MacKey)
		if err != nil || len(macKey) != 32 {
			fmt.Println("[⚠ stored mac key malformed]")
			return
		}
		copy(inner[off+2:off+2+32], macKey)
	}
	slot, err := encodeRatchetSlot(activeContact.R, inner)
	if err != nil {
		fmt.Println("[⚠ burn encrypt failed:", err, "]")
		return
	}
	enqueueSlot(slot)
	activeContact.Burned = true
	fmt.Printf("[🔥 burn queued — %d of your mac keys will be published. Conversation is now read-only.]\n", len(entries))
}

func writeManifest(path string) {
	if activeContact == nil || activeContact.R == nil {
		fmt.Println("[no active conversation to export]")
		return
	}
	mine := make([]BurnedMAC, 0, len(activeContact.R.BurnedMACs))
	for _, e := range activeContact.R.BurnedMACs {
		mine = append(mine, BurnedMAC{Seq: e.Seq, MacKey: e.MacKey})
	}
	manifest := map[string]any{
		"burnedAt": time.Now().UTC().Format(time.RFC3339),
		"contact":  activeContact.SessionKeyB64,
		"note":     "These MAC keys can forge messages authenticating against this conversation's HMAC chain. The transcript is no longer a reliable record.",
		"mySent":   mine,
		"peerSent": activeContact.PeerBurnedMACs,
	}
	if path == "" {
		path = fmt.Sprintf("tacenda-burn-%d.json", time.Now().Unix())
	}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		fmt.Println("[⚠ manifest write failed:", err, "]")
		return
	}
	fmt.Printf("[manifest written: %s  (%d mine, %d peer)]\n", path, len(mine), len(activeContact.PeerBurnedMACs))
}

// ── Slot scheduler + send queue ─────────────────────────────────────────────
//
// Constant-rate broadcast: every slotInterval, the scheduler pops one slot
// from the queue and writes it to the WebSocket; if the queue is empty, it
// emits a slot of pure random bytes. Real and noise are indistinguishable.

var sendQueue = make(chan []byte, 64)

func enqueueSlot(slot []byte) {
	select {
	case sendQueue <- slot:
	default:
		// Queue full — drop to avoid blocking the caller. With slotInterval=2s
		// and capacity 64 this should never happen in normal use.
		printLine("[⚠ send queue full, dropping slot]")
	}
}

func slotScheduler() {
	ticker := time.NewTicker(time.Duration(slotIntervalMs) * time.Millisecond)
	defer ticker.Stop()
	for range ticker.C {
		var slot []byte
		select {
		case slot = <-sendQueue:
		default:
			slot = make([]byte, slotSize)
			if _, err := rand.Read(slot); err != nil {
				continue
			}
		}
		connMu.Lock()
		err := conn.WriteMessage(websocket.BinaryMessage, slot)
		connMu.Unlock()
		if err != nil {
			return
		}
	}
}

// ── WebSocket I/O ───────────────────────────────────────────────────────────

func readLoop() {
	for {
		mt, data, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("\n[disconnected]")
			os.Exit(0)
		}
		if mt != websocket.BinaryMessage || len(data) != slotSize {
			continue
		}
		handleSlot(data)
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
	case "/burn":
		burnConversation()
	case "/manifest":
		path := ""
		if len(parts) >= 2 {
			path = parts[1]
		}
		writeManifest(path)
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
  /burn                       publish your past mac keys; locks the chat (deniable transcript)
  /manifest [path]            export burn manifest (your mac keys + peer's) to JSON
  /help                       show this help
  /quit                       exit
  <anything else>             send encrypted message to active contact

incoming handshakes set the new contact as active automatically; reply by typing.`)
}
