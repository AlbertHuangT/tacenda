const http = require("http");
const fs   = require("fs");
const path = require("path");
const WebSocket = require("ws");

// Routing table: publicKey (base64 SPKI) -> WebSocket connection
// In-memory only — nothing persists, disconnect removes the entry immediately
const clients = new Map();

// ── HTTP server: serves index.html ────────────────────────────────────────────
const server = http.createServer((req, res) => {
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    fs.readFile(path.join(__dirname, "index.html"), (err, data) => {
      if (err) { res.writeHead(500); res.end("error"); return; }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(data);
    });
  } else {
    res.writeHead(404); res.end("not found");
  }
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
  console.log(`RSA chat server → http://localhost:${PORT}`);
});
