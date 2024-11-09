export declare function getWebSocketClient(url: string, origin?: string): WebSocket | import("ws").WebSocket;
export type WebSocketClient = ReturnType<typeof getWebSocketClient>;
