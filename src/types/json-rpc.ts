export interface JsonRpcRequest {
  jsonrpc: string;
  id: string;
  method: string;
  params: any;
}

export interface JsonRpcResponse {
  jsonrpc: string;
  id: string;
  result: any;
}
