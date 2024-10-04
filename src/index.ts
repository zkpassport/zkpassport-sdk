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
import { bytesToHex } from "@noble/ciphers/utils";
import constants from "./constants";
import { getWebSocketClient, WebSocketClient } from "./websocket";
import { createJsonRpcRequest } from "./json-rpc";
import { decrypt, generateECDHKeyPair, getSharedSecret } from "./encryption";
import { JsonRpcRequest } from "./types/json-rpc";

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

export class ZkPassport {
  private domain: string;
  private topicToConfig: Record<string, Record<string, IDCredentialConfig>> =
    {};
  private topicToKeyPair: Record<
    string,
    { privateKey: Uint8Array; publicKey: Uint8Array }
  > = {};
  private topicToWebSocketClient: Record<string, WebSocketClient> = {};
  private topicToSharedSecret: Record<string, Uint8Array> = {};

  constructor(_domain: string) {
    this.domain = _domain;
  }

  private getZkPassportRequest(topic: string) {
    return {
      eq: <T extends IDCredential>(key: T, value: IDCredentialValue<T>) => {
        generalCompare("eq", key, value, topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      gte: <T extends NumericalIDCredential>(
        key: T,
        value: IDCredentialValue<T>
      ) => {
        numericalCompare("gte", key, value, topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      gt: <T extends NumericalIDCredential>(
        key: T,
        value: IDCredentialValue<T>
      ) => {
        numericalCompare("gt", key, value, topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      lte: <T extends NumericalIDCredential>(
        key: T,
        value: IDCredentialValue<T>
      ) => {
        numericalCompare("lte", key, value, topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      lt: <T extends NumericalIDCredential>(
        key: T,
        value: IDCredentialValue<T>
      ) => {
        numericalCompare("lt", key, value, topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      range: <T extends NumericalIDCredential>(
        key: T,
        start: IDCredentialValue<T>,
        end: IDCredentialValue<T>
      ) => {
        rangeCompare(key, [start, end], topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      in: <T extends IDCredential>(key: T, value: IDCredentialValue<T>[]) => {
        generalCompare("in", key, value, topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      out: <T extends IDCredential>(key: T, value: IDCredentialValue<T>[]) => {
        generalCompare("out", key, value, topic, this.topicToConfig);
        return this.getZkPassportRequest(topic);
      },
      checkAML: (country?: CountryName | Alpha2Code | Alpha3Code) => {
        return this.getZkPassportRequest(topic);
      },
      done: () => {
        const base64Config = Buffer.from(
          JSON.stringify(this.topicToConfig[topic])
        ).toString("base64");
        const pubkey = bytesToHex(this.topicToKeyPair[topic].publicKey);
        return {
          url: `https://zkpassport.id/request?d=${this.domain}&t=${topic}&c=${base64Config}&p=${pubkey}`,
          requestId: topic,
          onQRCodeScanned: (callback: () => void) => {
            this.onQRCodeScanned(topic, callback);
          },
          onGeneratingProof: (callback: () => void) => {
            this.onGeneratingProof(topic, callback);
          },
          onSuccess: (callback: (proof: ProofData) => void) => {
            this.onSuccess(topic, callback);
          },
          onError: (callback: (error: any) => void) => {
            this.onError(topic, callback);
          },
        };
      },
    };
  }

  /**
   * @notice Create a new request.
   * @returns The query builder object.
   */
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
    wsClient.addEventListener("message", async (event: any) => {
      console.log("Received message:", event.data);
      try {
        const data: JsonRpcRequest = JSON.parse(event.data);
        if (data.method === "handshake") {
          this.topicToSharedSecret[topic] = await getSharedSecret(
            bytesToHex(keyPair.privateKey),
            data.params.pubkey
          );
        }
      } catch (error) {}
    });
    wsClient.onerror = (error: Event) => {
      console.error("WebSocket error:", error);
    };
    return this.getZkPassportRequest(topic);
  }

  /**
   * @notice Verifies a proof.
   * @param proof The proof to verify.
   * @returns True if the proof is valid, false otherwise.
   */
  public verify(proof: Proof) {
    const backend = new UltraHonkBackend(proofOfAgeCircuit as CompiledCircuit);
    const proofData: ProofData = {
      proof: Buffer.from(proof.proof, "hex"),
      publicInputs: proof.publicInputs,
    };
    return backend.verifyProof(proofData);
  }

  /**
   * @notice Returns the URL of the request.
   * @param requestId The request ID.
   * @returns The URL of the request.
   */
  public getUrl(requestId: string) {
    const pubkey = bytesToHex(this.topicToKeyPair[requestId].publicKey);
    return `https://zkpassport.id/request?d=${this.domain}&t=${requestId}&c=${this.topicToConfig[requestId]}&p=${pubkey}`;
  }

  /**
   * @notice Cancels a request by closing the WebSocket connection and deleting the associated data.
   * @param requestId The request ID.
   */
  public cancelRequest(requestId: string) {
    this.topicToWebSocketClient[requestId].close();
    delete this.topicToWebSocketClient[requestId];
    delete this.topicToKeyPair[requestId];
    delete this.topicToConfig[requestId];
  }

  private handleMessage(topic: string, cipher: any, method: string) {
    const dataString = decrypt(cipher, this.topicToSharedSecret[topic], topic);
    const data: JsonRpcRequest = JSON.parse(dataString);
    if (data.method === method) {
      return data;
    }
  }

  private checkIfRequestExists(topic: string) {
    if (!this.topicToWebSocketClient[topic]) {
      throw new Error("Request not found");
    }
  }

  public onQRCodeScanned(topic: string, callback: () => void) {
    this.checkIfRequestExists(topic);
    this.topicToWebSocketClient[topic].addEventListener(
      "message",
      (event: any) => {
        const data = this.handleMessage(
          topic,
          event.data,
          "on_qr_code_scanned"
        );
        if (data) {
          callback();
        }
      }
    );
  }

  public onGeneratingProof(topic: string, callback: () => void) {
    this.checkIfRequestExists(topic);
    this.topicToWebSocketClient[topic].addEventListener(
      "message",
      (event: any) => {
        const data = this.handleMessage(
          topic,
          event.data,
          "on_generating_proof"
        );
        if (data) {
          callback();
        }
      }
    );
  }

  public onSuccess(topic: string, callback: (proof: ProofData) => void) {
    this.checkIfRequestExists(topic);
    this.topicToWebSocketClient[topic].addEventListener(
      "message",
      (event: any) => {
        const data = this.handleMessage(topic, event.data, "on_success");
        if (data) {
          callback(data.params);
        }
      }
    );
  }

  public onError(topic: string, callback: (error: any) => void) {
    this.checkIfRequestExists(topic);
    this.topicToWebSocketClient[topic].addEventListener(
      "message",
      (event: any) => {
        const data = this.handleMessage(topic, event.data, "on_error");
        if (data) {
          callback(data.params);
        }
      }
    );
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

  const {
    url,
    requestId,
    onQRCodeScanned,
    onGeneratingProof,
    onSuccess,
    onError,
  } = queryBuilder
    .eq("fullname", "John Doe")
    .range("age", 18, 25)
    .in("nationality", ["USA", "GBR", "Germany", "Canada", "Portugal"])
    .out("nationality", constants.countries.SANCTIONED)
    .checkAML()
    .done();

  console.log(url);
}

main();
