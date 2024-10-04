import { randomBytes } from "crypto";
import { JsonRpcRequest, JsonRpcResponse } from "./types/json-rpc";

export function createJsonRpcRequest(
  method: string,
  params: any
): JsonRpcRequest {
  return {
    jsonrpc: "2.0",
    id: randomBytes(16).toString("hex"),
    method,
    params,
  };
}

export function createJsonRpcResponse(
  id: string,
  result: any
): JsonRpcResponse {
  return {
    jsonrpc: "2.0",
    id,
    result,
  };
}
