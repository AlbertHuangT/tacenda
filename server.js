const http = require("http");
const fs   = require("fs");
const path = require("path");
const WebSocket = require("ws");

// Routing table: publicKey (base64 SPKI) -> WebSocket connection
// In-memory only — nothing persists, disconnect removes the entry immediately
const clients = new Map();

// ── HTTP server: serves static pages from ./public ───────────────────────────
const PUBLIC = path.join(__dirname, "public");

// Map clean URL paths to filenames in ./public
const ROUTES = {
  "/":           "index.html",
  "/index.html": "index.html",
  "/chat":       "chat.html",
  "/chat.html":  "chat.html",
  "/keygen":     "keygen.html",
  "/keygen.html":"keygen.html",
};

const server = http.createServer((req, res) => {
  if (req.method !== "GET") { res.writeHead(405); res.end(); return; }
  const { pathname } = new URL(req.url, "http://localhost");
  const file = ROUTES[pathname];
  if (!file) { res.writeHead(404); res.end("not found"); return; }
  fs.readFile(path.join(PUBLIC, file), (err, data) => {
    if (err) { res.writeHead(404); res.end("not found"); return; }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(data);
  });
});

// ── WebSocket server on /ws ───────────────────────────────────────────────────
const wss = new WebSocket.Server({ noServer: true });

server.on("upgrade", (request, socket, head) => {
  const { pathname } = new URL(request.url, "http://localhost");
  if (pathname === "/ws") {
    wss.handleUpgrade(request, socket, head, (ws) => wss.emit("connection", ws));
  } else {
    socket.destroy();
  }
});

wss.on("connection", function (ws) {
  let registeredKey = null;

  ws.on("message", function (data) {
    let msg;
    try { msg = JSON.parse(data); } catch { return; }

    if (msg.type === "register" && typeof msg.publicKey === "string") {
      registeredKey = msg.publicKey;
      clients.set(registeredKey, ws);
      console.log(`client registered  (${clients.size} online)`);

    } else if (msg.type === "handshake_broadcast" &&
               typeof msg.payload === "string" &&
               typeof msg.senderSession === "string") {
      if (msg.payload.length > 512 || msg.senderSession.length > 512) return;
      const outbound = JSON.stringify({
        type: "handshake_broadcast",
        payload: msg.payload,
        senderSession: msg.senderSession,
      });
      wss.clients.forEach(client => {
        if (client !== ws && client.readyState === WebSocket.OPEN) {
          client.send(outbound);
        }
      });

    } else if (msg.type === "message" && typeof msg.to === "string") {
      const recipientWs = clients.get(msg.to);
      if (recipientWs && recipientWs.readyState === WebSocket.OPEN) {
        recipientWs.send(JSON.stringify({
          type: "message",
          payload: msg.payload,
          senderKey: msg.senderKey ?? null,
        }));
      } else {
        ws.send(JSON.stringify({ type: "error", message: "recipient not online" }));
      }
    }
  });

  ws.on("close", () => {
    if (registeredKey) {
      clients.delete(registeredKey);
      console.log(`client left        (${clients.size} online)`);
    }
  });
});

// ── Listen ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Tacenda server → http://localhost:${PORT}`);
});
