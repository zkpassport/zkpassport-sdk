import { randomBytes } from 'crypto'
import { Alpha3Code, getAlpha3Code, registerLocale } from 'i18n-iso-countries'
import {
  type DisclosableIDCredential,
  type IDCredential,
  type IDCredentialConfig,
  type IDCredentialValue,
  type NumericalIDCredential,
  type ProofResult,
  type QueryResult,
  type CountryName,
  type JsonRpcRequest,
  getProofData,
  getHostedPackagedCircuitByName,
} from '@zkpassport/utils'
import { bytesToHex } from '@noble/ciphers/utils'
import { getWebSocketClient, WebSocketClient } from './websocket'
import { createEncryptedJsonRpcRequest } from './json-rpc'
import { decrypt, generateECDHKeyPair, getSharedSecret } from './encryption'
import logger from './logger'
import { BarretenbergVerifier } from '@aztec/bb.js'
import { ungzip } from 'node-gzip'

registerLocale(require('i18n-iso-countries/langs/en.json'))

function normalizeCountry(country: CountryName | Alpha3Code) {
  let normalizedCountry: Alpha3Code | undefined
  const alpha3 = getAlpha3Code(country, 'en') as Alpha3Code | undefined
  normalizedCountry = alpha3 || (country as Alpha3Code)
  return normalizedCountry
}

function numericalCompare(
  fnName: 'gte' | 'gt' | 'lte' | 'lt',
  key: NumericalIDCredential,
  value: number | Date,
  requestId: string,
  requestIdToConfig: Record<string, Record<string, IDCredentialConfig>>,
) {
  requestIdToConfig[requestId][key] = {
    ...requestIdToConfig[requestId][key],
    [fnName]: value,
  }
}

function rangeCompare(
  key: NumericalIDCredential,
  value: [number | Date, number | Date],
  requestId: string,
  requestIdToConfig: Record<string, Record<string, IDCredentialConfig>>,
) {
  requestIdToConfig[requestId][key] = {
    ...requestIdToConfig[requestId][key],
    range: value,
  }
}

function generalCompare(
  fnName: 'in' | 'out' | 'eq',
  key: IDCredential,
  value: any,
  requestId: string,
  requestIdToConfig: Record<string, Record<string, IDCredentialConfig>>,
) {
  requestIdToConfig[requestId][key] = {
    ...requestIdToConfig[requestId][key],
    [fnName]: value,
  }
}

export type * from '@zkpassport/utils'
export {
  SANCTIONED_COUNTRIES,
  EU_COUNTRIES,
  EEA_COUNTRIES,
  SCHENGEN_COUNTRIES,
  ASEAN_COUNTRIES,
  MERCOSUR_COUNTRIES,
} from '@zkpassport/utils'

export type QueryBuilderResult = {
  url: string
  requestId: string
  onQRCodeScanned: (callback: () => void) => void
  onGeneratingProof: (callback: () => void) => void
  onBridgeConnect: (callback: () => void) => void
  onProofGenerated: (callback: (proof: ProofResult) => void) => void
  onResult: (
    callback: (response: {
      uniqueIdentifier: string
      verified: boolean
      result: QueryResult
    }) => void,
  ) => void
  onReject: (callback: () => void) => void
  onError: (callback: (error: string) => void) => void
  isBridgeConnected: () => boolean
  isQRCodeScanned: () => boolean
}

export type QueryBuilder = {
  eq: <T extends IDCredential>(key: T, value: IDCredentialValue<T>) => QueryBuilder
  gte: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => QueryBuilder
  lte: <T extends 'birthdate' | 'expiry_date'>(key: T, value: IDCredentialValue<T>) => QueryBuilder
  lt: <T extends 'age'>(key: T, value: IDCredentialValue<T>) => QueryBuilder
  range: <T extends NumericalIDCredential>(
    key: T,
    start: IDCredentialValue<T>,
    end: IDCredentialValue<T>,
  ) => QueryBuilder
  in: <T extends 'nationality'>(key: T, value: IDCredentialValue<T>[]) => QueryBuilder
  out: <T extends 'nationality'>(key: T, value: IDCredentialValue<T>[]) => QueryBuilder
  disclose: (key: DisclosableIDCredential) => QueryBuilder
  done: () => QueryBuilderResult
}

export class ZKPassport {
  private domain: string
  private topicToConfig: Record<string, Record<string, IDCredentialConfig>> = {}
  private topicToKeyPair: Record<string, { privateKey: Uint8Array; publicKey: Uint8Array }> = {}
  private topicToWebSocketClient: Record<string, WebSocketClient> = {}
  private topicToSharedSecret: Record<string, Uint8Array> = {}
  private topicToQRCodeScanned: Record<string, boolean> = {}
  private topicToService: Record<
    string,
    { name: string; logo: string; purpose: string; scope?: string }
  > = {}
  private topicToProofs: Record<string, Array<ProofResult>> = {}

  private onQRCodeScannedCallbacks: Record<string, Array<() => void>> = {}
  private onGeneratingProofCallbacks: Record<string, Array<(topic: string) => void>> = {}
  private onBridgeConnectCallbacks: Record<string, Array<() => void>> = {}
  private onProofGeneratedCallbacks: Record<string, Array<(proof: ProofResult) => void>> = {}
  private onResultCallbacks: Record<
    string,
    Array<(response: { uniqueIdentifier: string; verified: boolean; result: QueryResult }) => void>
  > = {}
  private onRejectCallbacks: Record<string, Array<() => void>> = {}
  private onErrorCallbacks: Record<string, Array<(topic: string) => void>> = {}

  constructor(_domain?: string) {
    if (!_domain && typeof window === 'undefined') {
      throw new Error('Domain argument is required in Node.js environment')
    }
    this.domain = _domain || window.location.hostname
  }

  /**
   * @notice Handle an encrypted message.
   * @param request The request.
   * @param outerRequest The outer request.
   */
  private async handleEncryptedMessage(
    topic: string,
    request: JsonRpcRequest,
    outerRequest: JsonRpcRequest,
  ) {
    logger.debug('Received encrypted message:', request)
    if (request.method === 'accept') {
      logger.debug(`User accepted the request and is generating a proof`)
      await Promise.all(this.onGeneratingProofCallbacks[topic].map((callback) => callback(topic)))
    } else if (request.method === 'reject') {
      logger.debug(`User rejected the request`)
      await Promise.all(this.onRejectCallbacks[topic].map((callback) => callback()))
    } else if (request.method === 'proof') {
      logger.debug(`User generated proof`)
      // Uncompress the proof and convert it to a hex string
      const bytesProof = Buffer.from(request.params.proof, 'base64')
      const uncompressedProof = await ungzip(bytesProof)
      // The gzip lib in the app compress the proof as ASCII
      // and since the app passes the proof as a hex string, we can
      // just decode the bytes as hex characters using the TextDecoder
      const hexProof = new TextDecoder().decode(uncompressedProof)
      const processedProof: ProofResult = {
        proof: hexProof,
        vkeyHash: request.params.vkeyHash,
        name: request.params.name,
        version: request.params.version,
      }
      this.topicToProofs[topic].push(processedProof)
      await Promise.all(
        this.onProofGeneratedCallbacks[topic].map((callback) => callback(processedProof)),
      )
    } else if (request.method === 'done') {
      logger.debug(`User sent the query result`)
      // Verify the proofs and extract the unique identifier (aka nullifier) and the verification result
      const { uniqueIdentifier, verified } = await this.verify(
        topic,
        this.topicToProofs[topic],
        request.params,
      )
      await Promise.all(
        this.onResultCallbacks[topic].map((callback) =>
          callback({
            uniqueIdentifier,
            verified,
            result: request.params,
          }),
        ),
      )
    } else if (request.method === 'error') {
      await Promise.all(
        this.onErrorCallbacks[topic].map((callback) => callback(request.params.error)),
      )
    }
  }

  private getZkPassportRequest(topic: string): QueryBuilder {
    return {
      eq: <T extends IDCredential>(key: T, value: IDCredentialValue<T>) => {
        if (key === 'issuing_country' || key === 'nationality') {
          value = normalizeCountry(value as CountryName) as IDCredentialValue<T>
        }
        generalCompare('eq', key, value, topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },
      gte: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => {
        numericalCompare('gte', key, value, topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },
      /*gt: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => {
        numericalCompare('gt', key, value, topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },*/
      lte: <T extends 'birthdate' | 'expiry_date'>(key: T, value: IDCredentialValue<T>) => {
        numericalCompare('lte', key, value, topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },
      lt: <T extends 'age'>(key: T, value: IDCredentialValue<T>) => {
        numericalCompare('lt', key, value, topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },
      range: <T extends NumericalIDCredential>(
        key: T,
        start: IDCredentialValue<T>,
        end: IDCredentialValue<T>,
      ) => {
        rangeCompare(key, [start, end], topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },
      in: <T extends 'nationality'>(key: T, value: IDCredentialValue<T>[]) => {
        value = value.map((v) => normalizeCountry(v as CountryName)) as IDCredentialValue<T>[]
        generalCompare('in', key, value, topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },
      out: <T extends 'nationality'>(key: T, value: IDCredentialValue<T>[]) => {
        value = value.map((v) => normalizeCountry(v as CountryName)) as IDCredentialValue<T>[]
        generalCompare('out', key, value, topic, this.topicToConfig)
        return this.getZkPassportRequest(topic)
      },
      disclose: (key: DisclosableIDCredential) => {
        this.topicToConfig[topic][key] = {
          ...this.topicToConfig[topic][key],
          disclose: true,
        }
        return this.getZkPassportRequest(topic)
      },
      /*checkAML: (country?: CountryName | Alpha2Code | Alpha3Code) => {
        return this.getZkPassportRequest(topic)
      },*/
      done: () => {
        const base64Config = Buffer.from(JSON.stringify(this.topicToConfig[topic])).toString(
          'base64',
        )
        const base64Service = Buffer.from(JSON.stringify(this.topicToService[topic])).toString(
          'base64',
        )
        const pubkey = bytesToHex(this.topicToKeyPair[topic].publicKey)
        return {
          url: `https://zkpassport.id/r?d=${this.domain}&t=${topic}&c=${base64Config}&s=${base64Service}&p=${pubkey}`,
          requestId: topic,
          onQRCodeScanned: (callback: () => void) =>
            this.onQRCodeScannedCallbacks[topic].push(callback),
          onGeneratingProof: (callback: () => void) =>
            this.onGeneratingProofCallbacks[topic].push(callback),
          onBridgeConnect: (callback: () => void) =>
            this.onBridgeConnectCallbacks[topic].push(callback),
          onProofGenerated: (callback: (proof: ProofResult) => void) =>
            this.onProofGeneratedCallbacks[topic].push(callback),
          onResult: (
            callback: (response: {
              uniqueIdentifier: string
              verified: boolean
              result: QueryResult
            }) => void,
          ) => this.onResultCallbacks[topic].push(callback),
          onReject: (callback: () => void) => this.onRejectCallbacks[topic].push(callback),
          onError: (callback: (error: string) => void) =>
            this.onErrorCallbacks[topic].push(callback),
          isBridgeConnected: () => this.topicToWebSocketClient[topic].readyState === WebSocket.OPEN,
          isQRCodeScanned: () => this.topicToQRCodeScanned[topic] === true,
        }
      },
    }
  }

  /**
   * @notice Create a new request.
   * @returns The query builder object.
   */
  public async request({
    name,
    logo,
    purpose,
    scope,
    topicOverride,
    keyPairOverride,
  }: {
    name: string
    logo: string
    purpose: string
    scope?: string
    topicOverride?: string
    keyPairOverride?: { privateKey: Uint8Array; publicKey: Uint8Array }
  }) {
    const topic = topicOverride || randomBytes(16).toString('hex')

    const keyPair = keyPairOverride || (await generateECDHKeyPair())
    this.topicToKeyPair[topic] = {
      privateKey: keyPair.privateKey,
      publicKey: keyPair.publicKey,
    }

    this.topicToConfig[topic] = {}
    this.topicToService[topic] = { name, logo, purpose, scope }
    this.topicToProofs[topic] = []

    this.onQRCodeScannedCallbacks[topic] = []
    this.onGeneratingProofCallbacks[topic] = []
    this.onBridgeConnectCallbacks[topic] = []
    this.onProofGeneratedCallbacks[topic] = []
    this.onResultCallbacks[topic] = []
    this.onRejectCallbacks[topic] = []
    this.onErrorCallbacks[topic] = []

    const wsClient = getWebSocketClient(`wss://bridge.zkpassport.id?topic=${topic}`, this.domain)
    this.topicToWebSocketClient[topic] = wsClient
    wsClient.onopen = async () => {
      logger.info('[frontend] WebSocket connection established')
      await Promise.all(this.onBridgeConnectCallbacks[topic].map((callback) => callback()))
    }
    wsClient.addEventListener('message', async (event: any) => {
      logger.debug('[frontend] Received message:', event.data)
      try {
        const data: JsonRpcRequest = JSON.parse(event.data)
        // Handshake happens when the mobile app scans the QR code and connects to the bridge
        if (data.method === 'handshake') {
          logger.debug('[frontend] Received handshake:', event.data)

          this.topicToQRCodeScanned[topic] = true
          this.topicToSharedSecret[topic] = await getSharedSecret(
            bytesToHex(keyPair.privateKey),
            data.params.pubkey,
          )
          logger.debug(
            '[frontend] Shared secret:',
            Buffer.from(this.topicToSharedSecret[topic]).toString('hex'),
          )

          const encryptedMessage = await createEncryptedJsonRpcRequest(
            'hello',
            null,
            this.topicToSharedSecret[topic],
            topic,
          )
          logger.debug('[frontend] Sending encrypted message:', encryptedMessage)
          wsClient.send(JSON.stringify(encryptedMessage))

          await Promise.all(this.onQRCodeScannedCallbacks[topic].map((callback) => callback()))
          return
        }

        // Handle encrypted messages
        if (data.method === 'encryptedMessage') {
          // Decode the payload from base64 to Uint8Array
          const payload = new Uint8Array(
            atob(data.params.payload)
              .split('')
              .map((c) => c.charCodeAt(0)),
          )
          try {
            // Decrypt the payload using the shared secret
            const decrypted = await decrypt(payload, this.topicToSharedSecret[topic], topic)
            const decryptedJson: JsonRpcRequest = JSON.parse(decrypted)
            this.handleEncryptedMessage(topic, decryptedJson, data)
          } catch (error) {
            logger.error('[frontend] Error decrypting message:', error)
          }
          return
        }
      } catch (error) {
        logger.error('[frontend] Error:', error)
      }
    })
    wsClient.onerror = (error: Event) => {
      logger.error('[frontend] WebSocket error:', error)
    }
    return this.getZkPassportRequest(topic)
  }

  /**
   * @notice Verify the proofs received from the mobile app.
   * @param requestId The request ID.
   * @param proofs The proofs to verify.
   * @param queryResult The query result to verify against
   * @returns True if the proofs are valid, false otherwise.
   */
  public async verify(
    requestId: string,
    proofs?: Array<ProofResult>,
    queryResult?: QueryResult,
  ): Promise<{ uniqueIdentifier: string; verified: boolean }> {
    let proofsToVerify = proofs
    if (!proofs) {
      proofsToVerify = this.topicToProofs[requestId]
      if (!proofsToVerify) {
        throw new Error('No proofs to verify')
      }
    }
    const verifier = new BarretenbergVerifier()
    let verified = false
    for (const proof of proofsToVerify!) {
      const proofData = getProofData(proof.proof as string)
      console.log('proofData', proofData)
      const hostedPackagedCircuit = await getHostedPackagedCircuitByName(
        proof.version as any,
        proof.name!,
      )
      const vkeyBytes = Buffer.from(hostedPackagedCircuit.vkey, 'base64')
      console.log('proofData', proofData)
      verified = await verifier.verifyUltraHonkProof(proofData, new Uint8Array(vkeyBytes))
      console.log('verified', verified)
      if (!verified) {
        // Break the loop if the proof is not valid
        // and don't bother checking the other proofs
        break
      }
      // TODO: verify the proof public inputs against the query result
      // Use the name field in the retrieved packaged circuit to get which type of circuit it is
      // and thus what the public inputs to retrieve from the proof data
      // And extract the nullifier and provide it as return value to the verify function
    }
    delete this.topicToProofs[requestId]
    return { uniqueIdentifier: '', verified }
  }

  /**
   * @notice Returns the URL of the request.
   * @param requestId The request ID.
   * @returns The URL of the request.
   */
  public getUrl(requestId: string) {
    const pubkey = bytesToHex(this.topicToKeyPair[requestId].publicKey)
    const base64Config = Buffer.from(JSON.stringify(this.topicToConfig[requestId])).toString(
      'base64',
    )
    const base64Service = Buffer.from(JSON.stringify(this.topicToService[requestId])).toString(
      'base64',
    )
    return `https://zkpassport.id/r?d=${this.domain}&t=${requestId}&c=${base64Config}&s=${base64Service}&p=${pubkey}`
  }

  /**
   * @notice Cancels a request by closing the WebSocket connection and deleting the associated data.
   * @param requestId The request ID.
   */
  public cancelRequest(requestId: string) {
    this.topicToWebSocketClient[requestId].close()
    delete this.topicToWebSocketClient[requestId]
    delete this.topicToKeyPair[requestId]
    delete this.topicToConfig[requestId]
    delete this.topicToSharedSecret[requestId]
    delete this.topicToProofs[requestId]
    this.onQRCodeScannedCallbacks[requestId] = []
    this.onGeneratingProofCallbacks[requestId] = []
    this.onBridgeConnectCallbacks[requestId] = []
    this.onProofGeneratedCallbacks[requestId] = []
    this.onRejectCallbacks[requestId] = []
    this.onErrorCallbacks[requestId] = []
  }
}
