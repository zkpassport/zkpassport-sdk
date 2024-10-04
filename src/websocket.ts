export function getWebSocketClient(url: string) {
  if (typeof window !== "undefined" && window.WebSocket) {
    // Browser environment
    return new WebSocket(url);
  } else {
    // Node.js environment
    const WebSocket = require("ws");
    return new WebSocket(url) as import("ws").WebSocket;
  }
}

export type WebSocketClient = ReturnType<typeof getWebSocketClient>;
