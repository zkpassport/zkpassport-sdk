import { JsonRpcRequest, JsonRpcResponse } from './types/json-rpc';
import { WebSocketClient } from './websocket';
export declare function createJsonRpcRequest(method: string, params: any): JsonRpcRequest;
export declare function createEncryptedJsonRpcRequest(method: string, params: any, sharedSecret: Uint8Array, topic: string): Promise<JsonRpcRequest>;
export declare function sendEncryptedJsonRpcRequest(method: string, params: any, sharedSecret: Uint8Array, topic: string, wsClient: WebSocketClient): Promise<boolean>;
export declare function createJsonRpcResponse(id: string, result: any): JsonRpcResponse;
