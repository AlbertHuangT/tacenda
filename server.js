const WebSocket = require("ws");

const wss = new WebSocket.Server({ port: 3000 });

console.log("server initiated. port 3000");

wss.on("connection", function (ws) {
  console.log("someone connected");

  //received message
  ws.on("message", function (data) {
    const msg = JSON.parse(data);
    console.log("received message: ", msg);
  });
});
