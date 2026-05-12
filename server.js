const http = require("http");
const fs   = require("fs");
const path = require("path");
const WebSocket = require("ws");

// Anonymous broadcast room (Phase 3): every client emits a fixed-size 1024-byte
// binary slot at a fixed cadence. Real ciphertext and pure noise are
// indistinguishable on the wire. Server checks length and broadcasts; it has
// no per-client state, no JSON parsing, no idea what slots contain.

const PUBLIC = path.join(__dirname, "public");
const SLOT_SIZE = 1024;

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

wss.on("connection", function (ws) {
  console.log(`client joined  (${wss.clients.size} online)`);
  ws.on("message", function (data, isBinary) {
    // Phase 3: only fixed-length binary slots are valid; anything else is dropped.
    if (!isBinary || data.length !== SLOT_SIZE) return;
    for (const client of wss.clients) {
      if (client !== ws && client.readyState === WebSocket.OPEN) {
        client.send(data, { binary: true });
      }
    }
  });
  ws.on("close", () => console.log(`client left    (${wss.clients.size} online)`));
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Tacenda server → http://localhost:${PORT}  (slot=${SLOT_SIZE}B)`);
});
