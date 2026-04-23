// ─── Worker entry point ───────────────────────────────────────────────────────
// Routes /ws to the ChatRoom Durable Object; everything else is served as a
// static asset from the ./public directory.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/ws") {
      // All WebSocket connections share one Durable Object instance ("main"),
      // which holds the in-memory routing table for the lifetime of the DO.
      const id = env.CHAT.idFromName("main");
      const stub = env.CHAT.get(id);
      return stub.fetch(request);
    }

    return env.ASSETS.fetch(request);
  },
};

// ─── ChatRoom Durable Object ──────────────────────────────────────────────────
// One instance handles all connected WebSocket clients.
// Routing table is maintained via WebSocket attachments — no external storage.
// When a client disconnects the entry is gone; nothing persists.

export class ChatRoom {
  constructor(state) {
    this.state = state;
  }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket upgrade", { status: 426 });
    }

    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);

    // Hibernatable WebSocket API — the DO can sleep between messages
    this.state.acceptWebSocket(server);

    return new Response(null, { status: 101, webSocket: client });
  }

  // ── Incoming message handler ────────────────────────────────────────────────
  async webSocketMessage(ws, message) {
    let msg;
    try {
      msg = JSON.parse(message);
    } catch {
      return;
    }

    if (msg.type === "register" && typeof msg.publicKey === "string") {
      // Tag this socket with the client's public key (their routing address)
      ws.serializeAttachment({ publicKey: msg.publicKey });

    } else if (msg.type === "message" && typeof msg.to === "string") {
      // Walk all live sockets to find the recipient
      const sockets = this.state.getWebSockets();
      let routed = false;

      for (const socket of sockets) {
        const meta = socket.deserializeAttachment();
        if (meta?.publicKey === msg.to) {
          socket.send(JSON.stringify({
            type: "message",
            payload: msg.payload,          // hybrid-encrypted blob, never inspected
            senderKey: msg.senderKey ?? null,
          }));
          routed = true;
          break;
        }
      }

      if (!routed) {
        ws.send(JSON.stringify({ type: "error", message: "recipient not online" }));
      }
    }
  }

  async webSocketClose() {
    // Hibernatable API removes the socket from getWebSockets() automatically
  }

  async webSocketError(ws) {
    ws.close(1011, "internal error");
  }
}
