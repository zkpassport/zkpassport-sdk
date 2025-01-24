import { bytesToHex } from "@noble/ciphers/utils"
import { getSharedSecret } from "../../src/encryption"
import { MockWebSocket } from "./mock-websocket"
import { createEncryptedJsonRpcRequest } from "../../src/json-rpc"

export async function waitForCallback(callback: (resolve: () => void) => void): Promise<void> {
  return new Promise<void>((resolve) => {
    callback(resolve)
  })
}

export async function simulateHelloFromFrontend(
  wsClient: MockWebSocket,
  keyPairFrontend: any,
  keyPairMobile: any,
  topic: string,
) {
  const sharedSecret = await getSharedSecret(
    bytesToHex(keyPairFrontend.privateKey),
    bytesToHex(keyPairMobile.publicKey),
  )
  const encryptedMessage = await createEncryptedJsonRpcRequest("hello", null, sharedSecret, topic)
  encryptedMessage["origin"] = "https://localhost"
  wsClient.onmessageHandlers?.forEach((callback) =>
    callback({ data: JSON.stringify(encryptedMessage) }),
  )
}

export async function simulateHandshakeFromMobile(wsClient: MockWebSocket, publicKey: Uint8Array) {
  const message = {
    method: "handshake",
    params: { pubkey: bytesToHex(publicKey) },
    origin: "https://localhost",
  }
  wsClient.onmessageHandlers?.forEach((callback) => callback({ data: JSON.stringify(message) }))
}
