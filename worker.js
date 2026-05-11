// Worker entry: route /ws to the ChatRoom Durable Object; everything else is
// served as a static asset.
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === "/ws") {
      const id = env.CHAT.idFromName("main");
      const stub = env.CHAT.get(id);
      return stub.fetch(request);
    }
    return env.ASSETS.fetch(request);
  },
};

// ChatRoom Durable Object — anonymous broadcast room. Forwards every well-formed
// JSON envelope to all other connected sockets. No routing table, no per-client
// state. Clients use Double Ratchet + trial-decrypt to find their messages.
export class ChatRoom {
  constructor(state) { this.state = state; }

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("Expected WebSocket upgrade", { status: 426 });
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair);
    this.state.acceptWebSocket(server);
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    if (typeof message !== "string") message = new TextDecoder().decode(message);
    if (message.length > 8192) return;
    let msg;
    try { msg = JSON.parse(message); } catch { return; }
    if (msg.type !== "message" && msg.type !== "handshake_broadcast") return;
    for (const socket of this.state.getWebSockets()) {
      if (socket !== ws) socket.send(message);
    }
  }

  async webSocketClose() {}
  async webSocketError(ws) { ws.close(1011, "internal error"); }
}
