import { randomBytes } from "crypto";
import { Alpha2Code, Alpha3Code } from "i18n-iso-countries";
import {
  IDCredential,
  IDCredentialConfig,
  IDCredentialValue,
  NumericalIDCredential,
} from "./types/credentials";
import { Proof } from "./types/proof";
import { CountryName } from "./types/countries";
import {
  UltraHonkBackend,
  ProofData,
  CompiledCircuit,
} from "@noir-lang/backend_barretenberg";
import proofOfAgeCircuit from "./circuits/proof_age.json";
import { gcm } from "@noble/ciphers/aes";
import { bytesToHex, hexToBytes, utf8ToBytes } from "@noble/ciphers/utils";
import constants from "./constants";
import { getWebSocketClient, WebSocketClient } from "./websocket";
import { createJsonRpcRequest } from "./json-rpc";

function numericalCompare(
  fnName: "gte" | "gt" | "lte" | "lt",
  key: NumericalIDCredential,
  value: number | Date,
  requestId: string,
  requestIdToConfig: Record<string, Record<string, IDCredentialConfig>>
) {
  requestIdToConfig[requestId][key] = {
    ...requestIdToConfig[requestId][key],
    [fnName]: value,
  };
}

function rangeCompare(
  key: NumericalIDCredential,
  value: [number | Date, number | Date],
  requestId: string,
  requestIdToConfig: Record<string, Record<string, IDCredentialConfig>>
) {
  requestIdToConfig[requestId][key] = {
    ...requestIdToConfig[requestId][key],
    range: value,
  };
}

function generalCompare(
  fnName: "in" | "out" | "eq",
  key: IDCredential,
  value: any,
  requestId: string,
  requestIdToConfig: Record<string, Record<string, IDCredentialConfig>>
) {
  requestIdToConfig[requestId][key] = {
    ...requestIdToConfig[requestId][key],
    [fnName]: value,
  };
}

const getZkPassportRequest = (
  topicToConfig: Record<string, Record<string, IDCredentialConfig>>,
  domain: string,
  topic: string
) => ({
  eq: <T extends IDCredential>(key: T, value: IDCredentialValue<T>) => {
    generalCompare("eq", key, value, topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  gte: <T extends NumericalIDCredential>(
    key: T,
    value: IDCredentialValue<T>
  ) => {
    numericalCompare("gte", key, value, topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  gt: <T extends NumericalIDCredential>(
    key: T,
    value: IDCredentialValue<T>
  ) => {
    numericalCompare("gt", key, value, topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  lte: <T extends NumericalIDCredential>(
    key: T,
    value: IDCredentialValue<T>
  ) => {
    numericalCompare("lte", key, value, topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  lt: <T extends NumericalIDCredential>(
    key: T,
    value: IDCredentialValue<T>
  ) => {
    numericalCompare("lt", key, value, topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  range: <T extends NumericalIDCredential>(
    key: T,
    start: IDCredentialValue<T>,
    end: IDCredentialValue<T>
  ) => {
    rangeCompare(key, [start, end], topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  in: <T extends IDCredential>(key: T, value: IDCredentialValue<T>[]) => {
    generalCompare("in", key, value, topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  out: <T extends IDCredential>(key: T, value: IDCredentialValue<T>[]) => {
    generalCompare("out", key, value, topic, topicToConfig);
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  checkAML: (country?: CountryName | Alpha2Code | Alpha3Code) => {
    return getZkPassportRequest(topicToConfig, domain, topic);
  },
  getUrl: () => {
    const base64Config = Buffer.from(
      JSON.stringify(topicToConfig[topic])
    ).toString("base64");
    return `https://zkpassport.id/request?d=${domain}&t=${topic}&c=${base64Config}`;
  },
  getRequestId: () => {
    return topic;
  },
});

async function generateECDHKeyPair() {
  const secp256k1 = await import("@noble/secp256k1");
  const privKey = secp256k1.utils.randomPrivateKey();
  const pubKey = secp256k1.getPublicKey(privKey);
  return {
    privateKey: privKey,
    publicKey: pubKey,
  };
}

async function getSharedSecret(
  privateKey: `0x${string}`,
  publicKey: `0x${string}`
) {
  const secp256k1 = await import("@noble/secp256k1");
  return secp256k1.getSharedSecret(privateKey, publicKey);
}

function encrypt(message: string, sharedSecret: Uint8Array, topic: string) {
  const aes = gcm(sharedSecret, hexToBytes(topic));
  const data = utf8ToBytes(message);
  const ciphertext = aes.encrypt(data);
  return ciphertext;
}

function decrypt(
  ciphertext: Uint8Array,
  sharedSecret: Uint8Array,
  topic: string
) {
  const aes = gcm(sharedSecret, hexToBytes(topic));
  const data = aes.decrypt(ciphertext);
  return data;
}

export class ZkPassport {
  private domain: string;
  private topicToConfig: Record<string, Record<string, IDCredentialConfig>> =
    {};
  private topicToKeyPair: Record<
    string,
    { privateKey: Uint8Array; publicKey: Uint8Array }
  > = {};
  private topicToWebSocketClient: Record<string, WebSocketClient> = {};

  constructor(_domain: string) {
    this.domain = _domain;
  }

  public async request() {
    const keyPair = await generateECDHKeyPair();
    const topic = randomBytes(16).toString("hex");
    this.topicToKeyPair[topic] = {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    };
    this.topicToConfig[topic] = {};
    const wsClient = getWebSocketClient(
      `wss://bridge.zkpassport.id?topic=${topic}`
    );
    this.topicToWebSocketClient[topic] = wsClient;
    wsClient.onopen = () => {
      console.log("WebSocket connection established");
      wsClient.send(
        JSON.stringify(
          createJsonRpcRequest("handshake", {
            pubkey: bytesToHex(keyPair.publicKey),
          })
        )
      );
    };
    wsClient.onmessage = (event: MessageEvent) => {
      console.log("Received message:", event.data);
    };
    wsClient.onerror = (error: Event) => {
      console.error("WebSocket error:", error);
    };
    return getZkPassportRequest(this.topicToConfig, this.domain, topic);
  }

  public verify(proof: Proof) {
    const backend = new UltraHonkBackend(proofOfAgeCircuit as CompiledCircuit);
    const proofData: ProofData = {
      proof: Buffer.from(proof.proof, "hex"),
      publicInputs: proof.publicInputs,
    };
    return backend.verifyProof(proofData);
  }

  public getUrl(topic: string) {
    return `https://zkpassport.id/request?d=${this.domain}&t=${topic}&c=${this.topicToConfig[topic]}`;
  }
}

const zkPassport = new ZkPassport("devcon.org");

/*want to check "TUR" is not in the list 

find some j where countries[j] < TUR < countries[j+1]

With each letter converted to its ASCII value and the three letters forming a 24 bit number.

Example:
TUR -> 84 117 114
*/

async function main() {
  const queryBuilder = await zkPassport.request();

  const url = queryBuilder
    .eq("fullname", "John Doe")
    .range("age", 18, 25)
    .in("nationality", ["USA", "GBR", "Germany", "Canada", "Portugal"])
    .out("nationality", constants.countries.SANCTIONED)
    .checkAML()
    .getUrl();

  console.log(url);
}

main();
