import { Alpha2Code, Alpha3Code } from 'i18n-iso-countries';
import { DisclosableIDCredential, IDCredential, IDCredentialValue, NumericalIDCredential } from './types/credentials';
import { ProofResult } from './types/query-result';
import { CountryName } from './types/countries';
import constants from './constants';
export { constants };
export declare class ZkPassport {
    private domain;
    private topicToConfig;
    private topicToKeyPair;
    private topicToWebSocketClient;
    private topicToSharedSecret;
    private topicToQRCodeScanned;
    private onQRCodeScannedCallbacks;
    private onGeneratingProofCallbacks;
    private onBridgeConnectCallbacks;
    private onProofGeneratedCallbacks;
    private onRejectCallbacks;
    private onErrorCallbacks;
    private topicToService;
    constructor(_domain?: string);
    /**
     * @notice Handle an encrypted message.
     * @param request The request.
     * @param outerRequest The outer request.
     */
    private handleEncryptedMessage;
    private getZkPassportRequest;
    /**
     * @notice Create a new request.
     * @returns The query builder object.
     */
    request({ name, logo, purpose, topicOverride, keyPairOverride, }: {
        name: string;
        logo: string;
        purpose: string;
        topicOverride?: string;
        keyPairOverride?: {
            privateKey: Uint8Array;
            publicKey: Uint8Array;
        };
    }): Promise<{
        eq: <T extends IDCredential>(key: T, value: IDCredentialValue<T>) => any;
        gte: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => any;
        gt: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => any;
        lte: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => any;
        lt: <T extends NumericalIDCredential>(key: T, value: IDCredentialValue<T>) => any;
        range: <T extends NumericalIDCredential>(key: T, start: IDCredentialValue<T>, end: IDCredentialValue<T>) => any;
        in: <T extends IDCredential>(key: T, value: IDCredentialValue<T>[]) => any;
        out: <T extends IDCredential>(key: T, value: IDCredentialValue<T>[]) => any;
        disclose: (key: DisclosableIDCredential) => any;
        checkAML: (country?: CountryName | Alpha2Code | Alpha3Code) => any;
        done: () => {
            url: string;
            requestId: string;
            onQRCodeScanned: (callback: () => void) => number;
            onGeneratingProof: (callback: () => void) => number;
            onBridgeConnect: (callback: () => void) => number;
            onProofGenerated: (callback: (result: ProofResult) => void) => number;
            onReject: (callback: () => void) => number;
            onError: (callback: (error: string) => void) => number;
            isBridgeConnected: () => boolean;
            isQRCodeScanned: () => boolean;
        };
    }>;
    /**
     * @notice Verifies a proof.
     * @param proof The proof to verify.
     * @returns True if the proof is valid, false otherwise.
     */
    verify(result: ProofResult): void;
    /**
     * @notice Returns the URL of the request.
     * @param requestId The request ID.
     * @returns The URL of the request.
     */
    getUrl(requestId: string): string;
    /**
     * @notice Cancels a request by closing the WebSocket connection and deleting the associated data.
     * @param requestId The request ID.
     */
    cancelRequest(requestId: string): void;
}
