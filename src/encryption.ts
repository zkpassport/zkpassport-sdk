import { gcm } from "@noble/ciphers/aes";
import { hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";

export async function generateECDHKeyPair() {
  const secp256k1 = await import("@noble/secp256k1");
  const privKey = secp256k1.utils.randomPrivateKey();
  const pubKey = secp256k1.getPublicKey(privKey);
  return {
    privateKey: privKey,
    publicKey: pubKey,
  };
}

export async function getSharedSecret(privateKey: string, publicKey: string) {
  const secp256k1 = await import("@noble/secp256k1");
  return secp256k1.getSharedSecret(privateKey, publicKey);
}

export function encrypt(
  message: string,
  sharedSecret: Uint8Array,
  topic: string
) {
  const aes = gcm(sharedSecret, hexToBytes(topic));
  const data = utf8ToBytes(message);
  const ciphertext = aes.encrypt(data);
  return ciphertext;
}

export function decrypt(
  ciphertext: Uint8Array,
  sharedSecret: Uint8Array,
  topic: string
) {
  const aes = gcm(sharedSecret, hexToBytes(topic));
  const data = aes.decrypt(ciphertext);
  const dataString = new TextDecoder().decode(data);
  return dataString;
}
