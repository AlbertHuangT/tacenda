package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// ── Types ─────────────────────────────────────────────────────────────────────

// ChatPayload matches the web client's hybrid-encryption envelope: { k, iv, msg }
type ChatPayload struct {
	K   string `json:"k"`   // base64(RSA-OAEP wrapped AES key)
	IV  string `json:"iv"`  // base64(12-byte GCM nonce)
	Msg string `json:"msg"` // base64(AES-GCM-256 ciphertext)
}

// IncomingMessage is the raw shape arriving from the server.
// payload is json.RawMessage because it's a string for handshake_broadcast
// but an object for message — we unmarshal it lazily.
type IncomingMessage struct {
	Type          string          `json:"type"`
	Payload       json.RawMessage `json:"payload"`
	SenderKey     string          `json:"senderKey"`
	SenderSession string          `json:"senderSession"`
}

// Contact holds a peer's current session key (changes every time they reconnect).
type Contact struct {
	ID            int
	SessionKeyB64 string
	SessionPubKey *rsa.PublicKey
}

// ── Global state ──────────────────────────────────────────────────────────────

var (
	identityPrivKey  *rsa.PrivateKey
	sessionPrivKey   *rsa.PrivateKey
	sessionPubKeyB64 string // SPKI base64, same format as web client

	contacts      = map[int]*Contact{}
	contactsMu    sync.Mutex
	nextContactID = 1
	activeContact *Contact

	conn   *websocket.Conn
	connMu sync.Mutex
)

// ── Main ──────────────────────────────────────────────────────────────────────

func main() {
	keygenMode := flag.Bool("keygen", false, "generate a new long-term identity key pair and exit")
	keyOut     := flag.String("out", "identity.pem", "output path for --keygen (private key)")
	keyPath    := flag.String("key", "", "path to identity private key PEM file")
	server     := flag.String("server", "ws://localhost:3000/ws", "WebSocket server URL")
	flag.Parse()

	if *keygenMode {
		runKeygen(*keyOut)
		return
	}

	if *keyPath == "" {
		// Try default path ~/rsa-chat/identity.pem
		home, _ := os.UserHomeDir()
		defaultPath := filepath.Join(home, ".rsa-chat", "identity.pem")
		if _, err := os.Stat(defaultPath); err == nil {
			*keyPath = defaultPath
		}
	}

	if *keyPath != "" {
		var err error
		identityPrivKey, err = loadPrivKey(*keyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading key %s: %v\n", *keyPath, err)
			os.Exit(1)
		}
		identityPubB64 := pubKeyToB64(&identityPrivKey.PublicKey)
		fmt.Println("identity  :", truncate(identityPubB64, 48)+"...")
	} else {
		fmt.Println("no identity key loaded — handshake receive disabled (use --key or --keygen)")
	}

	// Generate a fresh session key pair on every startup (matches web client behaviour)
	var err error
	sessionPrivKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to generate session key:", err)
		os.Exit(1)
	}
	sessionPubKeyB64 = pubKeyToB64(&sessionPrivKey.PublicKey)
	fmt.Println("session   :", truncate(sessionPubKeyB64, 48)+"...")

	// Connect to server
	c, _, err := websocket.DefaultDialer.Dial(*server, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "connection failed:", err)
		os.Exit(1)
	}
	conn = c
	defer conn.Close()

	// Register session key
	sendJSON(map[string]any{
		"type":      "register",
		"publicKey": sessionPubKeyB64,
	})
	fmt.Println("connected :", *server)
	printHelp()

	// Start read loop in background
	go readLoop()

	// Input loop runs on main goroutine
	inputLoop()
}

// ── Key generation ────────────────────────────────────────────────────────────

func runKeygen(outPath string) {
	fmt.Println("generating RSA-2048 key pair…")
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintln(os.Stderr, "key generation failed:", err)
		os.Exit(1)
	}

	// Private key → PKCS#8 PEM (compatible with OpenSSL and web client's importKey("pkcs8"…))
	pkcs8Bytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "marshal failed:", err)
		os.Exit(1)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Bytes})

	if err := os.MkdirAll(filepath.Dir(outPath), 0700); err != nil && filepath.Dir(outPath) != "." {
		fmt.Fprintln(os.Stderr, "mkdir failed:", err)
		os.Exit(1)
	}
	if err := os.WriteFile(outPath, privPEM, 0600); err != nil {
		fmt.Fprintln(os.Stderr, "write failed:", err)
		os.Exit(1)
	}

	// Public key → SPKI base64 (same format the web client displays and exchanges)
	pubB64 := pubKeyToB64(&key.PublicKey)

	fmt.Println()
	fmt.Println("private key saved to:", outPath)
	fmt.Println()
	fmt.Println("your long-term public key — share this with friends (once, offline):")
	fmt.Println()
	fmt.Println(pubB64)
	fmt.Println()
	fmt.Println("keep identity.pem safe. anyone who obtains it can impersonate you.")
}

// ── WebSocket I/O ─────────────────────────────────────────────────────────────

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
		case "error":
			// Extract message field from raw JSON
			var raw map[string]string
			json.Unmarshal(data, &raw)
			printLine(fmt.Sprintf("[⚠ server: %s]", raw["message"]))
		}
	}
}

func handleHandshake(msg IncomingMessage) {
	if identityPrivKey == nil {
		return // no identity key loaded, can't decrypt handshakes
	}
	if msg.SenderSession == "" {
		return
	}

	// payload is a hybrid-encrypted { k, iv, msg } object (same format as chat messages)
	var payload ChatPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return
	}

	// Attempt hybrid decryption — fails silently if not addressed to us
	sessionKeyRaw, err := decryptMessage(identityPrivKey, &payload)
	if err != nil {
		return // not for us
	}

	// sessionKeyRaw is the raw SPKI DER bytes of the sender's session public key
	sessionKeyB64 := base64.StdEncoding.EncodeToString([]byte(sessionKeyRaw))

	// Integrity check: should match the plaintext senderSession field
	if sessionKeyB64 != msg.SenderSession {
		return
	}

	// Parse the session public key
	spkiBytes := []byte(sessionKeyRaw)
	pubKeyIface, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		return
	}
	rsaPubKey, ok := pubKeyIface.(*rsa.PublicKey)
	if !ok {
		return
	}

	contactsMu.Lock()
	id := nextContactID
	nextContactID++
	contacts[id] = &Contact{ID: id, SessionKeyB64: sessionKeyB64, SessionPubKey: rsaPubKey}
	contactsMu.Unlock()

	printLine(fmt.Sprintf("[!] handshake received → contact #%d\n    /accept %d  to start chatting", id, id))
}

func handleMessage(msg IncomingMessage) {
	var payload ChatPayload
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		printLine("[⚠ malformed message]")
		return
	}

	plaintext, err := decryptMessage(sessionPrivKey, &payload)
	if err != nil {
		printLine("[⚠ could not decrypt message — keys may not match]")
		return
	}

	// Identify which contact sent this (by senderKey session address)
	label := "?"
	contactsMu.Lock()
	if msg.SenderKey != "" {
		for _, c := range contacts {
			if c.SessionKeyB64 == msg.SenderKey {
				label = fmt.Sprintf("#%d", c.ID)
				break
			}
		}
		// Auto-register previously unknown sender (e.g. direct session-key chat)
		if label == "?" {
			spkiBytes, err := base64.StdEncoding.DecodeString(msg.SenderKey)
			if err == nil {
				if pk, err := x509.ParsePKIXPublicKey(spkiBytes); err == nil {
					if rsaPK, ok := pk.(*rsa.PublicKey); ok {
						id := nextContactID
						nextContactID++
						contacts[id] = &Contact{ID: id, SessionKeyB64: msg.SenderKey, SessionPubKey: rsaPK}
						label = fmt.Sprintf("#%d", id)
					}
				}
			}
		}
	}
	contactsMu.Unlock()

	ts := time.Now().Format("15:04")
	printLine(fmt.Sprintf("[%s] [%s] %s", ts, label, plaintext))
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

	case "/accept":
		if len(parts) < 2 {
			fmt.Println("usage: /accept <contact_id>")
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
		fmt.Println(sessionPubKeyB64)

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

func sendChatMessage(text string) {
	if activeContact == nil {
		fmt.Println("[no active contact — use /find or /accept first, then /chat <id>]")
		return
	}

	payload, err := encryptMessage(activeContact.SessionPubKey, text)
	if err != nil {
		fmt.Println("[⚠ encryption failed:", err, "]")
		return
	}

	sendJSON(map[string]any{
		"type":      "message",
		"to":        activeContact.SessionKeyB64,
		"payload":   payload,
		"senderKey": sessionPubKeyB64,
	})

	ts := time.Now().Format("15:04")
	fmt.Printf("[%s] [me] %s\n", ts, text)
}

func broadcastHandshake(friendLongTermPubB64 string) error {
	spkiBytes, err := base64.StdEncoding.DecodeString(friendLongTermPubB64)
	if err != nil {
		return fmt.Errorf("invalid base64: %w", err)
	}
	pubKeyIface, err := x509.ParsePKIXPublicKey(spkiBytes)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}
	friendPubKey, ok := pubKeyIface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA key")
	}

	// Encrypt MY session public key bytes with FRIEND's long-term public key.
	// Session public key SPKI is 294 bytes — exceeds RSA-OAEP's 190-byte limit,
	// so we use hybrid encryption (same AES-GCM + RSA-OAEP scheme as chat messages).
	sessionPubKeyBytes, _ := base64.StdEncoding.DecodeString(sessionPubKeyB64)
	payload, err := encryptMessage(friendPubKey, string(sessionPubKeyBytes))
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	return sendJSON(map[string]any{
		"type":          "handshake_broadcast",
		"payload":       payload,
		"senderSession": sessionPubKeyB64,
	})
}

// ── Crypto ────────────────────────────────────────────────────────────────────

// encryptMessage performs hybrid encryption identical to the web client:
// AES-GCM-256 for the message body + RSA-OAEP to wrap the AES key.
func encryptMessage(recipientPubKey *rsa.PublicKey, plaintext string) (*ChatPayload, error) {
	// Random AES-256 key
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, err
	}

	// Random 12-byte GCM nonce (web client uses 12 bytes)
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}

	// AES-GCM encrypt
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, iv, []byte(plaintext), nil)

	// RSA-OAEP wrap the AES key
	encAESKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, recipientPubKey, aesKey, nil)
	if err != nil {
		return nil, err
	}

	return &ChatPayload{
		K:   base64.StdEncoding.EncodeToString(encAESKey),
		IV:  base64.StdEncoding.EncodeToString(iv),
		Msg: base64.StdEncoding.EncodeToString(ciphertext),
	}, nil
}

// decryptMessage is the inverse of encryptMessage — matches web client's decryptPayload().
func decryptMessage(privKey *rsa.PrivateKey, payload *ChatPayload) (string, error) {
	encAESKey, err := base64.StdEncoding.DecodeString(payload.K)
	if err != nil {
		return "", err
	}
	iv, err := base64.StdEncoding.DecodeString(payload.IV)
	if err != nil {
		return "", err
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Msg)
	if err != nil {
		return "", err
	}

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privKey, encAESKey, nil)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plaintext, err := gcm.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

// ── Key helpers ───────────────────────────────────────────────────────────────

func loadPrivKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in %s", path)
	}
	keyIface, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ParsePKCS8PrivateKey: %w", err)
	}
	rsaKey, ok := keyIface.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not RSA")
	}
	return rsaKey, nil
}

// pubKeyToB64 exports an RSA public key as base64 SPKI — identical to the
// web client's: btoa(String.fromCharCode(...new Uint8Array(spkiArrayBuffer)))
func pubKeyToB64(pub *rsa.PublicKey) string {
	spki, _ := x509.MarshalPKIXPublicKey(pub)
	return base64.StdEncoding.EncodeToString(spki)
}

// ── Utilities ─────────────────────────────────────────────────────────────────

func sendJSON(v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	connMu.Lock()
	defer connMu.Unlock()
	return conn.WriteMessage(websocket.TextMessage, data)
}

// printLine prints a line above the current input prompt without garbling it.
func printLine(s string) {
	fmt.Printf("\r%s\n> ", s)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func printHelp() {
	fmt.Println(`
commands:
  /find <long_term_pub_key>   broadcast a handshake to a friend (paste their identity public key)
  /accept <n>                 accept an incoming handshake and set contact #n as active
  /chat <n>                   switch active contact
  /contacts                   list all known contacts (* = active)
  /mykey                      print your current session public key
  /help                       show this help
  /quit                       exit
  <anything else>             send encrypted message to active contact`)
}
