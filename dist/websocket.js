"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.getWebSocketClient = getWebSocketClient;
function getWebSocketClient(url, origin) {
    if (typeof window !== 'undefined' && window.WebSocket) {
        // Browser environment
        return new WebSocket(url);
    }
    else {
        // Node.js environment
        var WebSocket_1 = require('ws');
        return new WebSocket_1(url, {
            headers: {
                Origin: origin || 'nodejs',
            },
        });
    }
}
