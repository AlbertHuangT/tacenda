const http = require("http");
const fs   = require("fs");
const path = require("path");
const WebSocket = require("ws");

// Anonymous broadcast room: server forwards every well-formed JSON envelope to
// all other connected sockets. No routing table, no recipient lookup, no
// per-client state. Clients use Double Ratchet + trial-decrypt to find their
// own messages and ECIES sealed-box handshakes to bootstrap each conversation.

const PUBLIC = path.join(__dirname, "public");

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

const wss = new WebSocket.Server({ noServer: true });

server.on("upgrade", (request, socket, head) => {
  const { pathname } = new URL(request.url, "http://localhost");
  if (pathname === "/ws") {
    wss.handleUpgrade(request, socket, head, (ws) => wss.emit("connection", ws));
  } else {
    socket.destroy();
  }
});

const MAX_FRAME = 8192; // generous for ratchet headers; tightened to 1024 in Phase 3

wss.on("connection", function (ws) {
  console.log(`client joined  (${wss.clients.size} online)`);

  ws.on("message", function (data) {
    if (data.length > MAX_FRAME) return;
    const text = data.toString();
    // Light shape check so random TCP traffic doesn't get fanned out
    let msg;
    try { msg = JSON.parse(text); } catch { return; }
    if (msg.type !== "message" && msg.type !== "handshake_broadcast") return;

    for (const client of wss.clients) {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(text);
      }
    }
  });

  ws.on("close", () => {
    console.log(`client left    (${wss.clients.size} online)`);
  });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Tacenda server → http://localhost:${PORT}`);
});
