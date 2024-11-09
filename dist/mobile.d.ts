export declare class ZkPassportProver {
    private domain?;
    private topicToKeyPair;
    private topicToWebSocketClient;
    private topicToRemoteDomainVerified;
    private topicToSharedSecret;
    private topicToRemotePublicKey;
    private onDomainVerifiedCallbacks;
    private onBridgeConnectCallbacks;
    private onWebsiteDomainVerifyFailureCallbacks;
    constructor();
    /**
     * @notice Handle an encrypted message.
     * @param request The request.
     * @param outerRequest The outer request.
     */
    private handleEncryptedMessage;
    /**
     * @notice Scan a credentirequest QR code.
     * @returns
     */
    scan(url: string, { keyPairOverride, }?: {
        keyPairOverride?: {
            privateKey: Uint8Array;
            publicKey: Uint8Array;
        };
    }): Promise<{
        domain: string;
        requestId: string;
        isBridgeConnected: () => boolean;
        isDomainVerified: () => boolean;
        onDomainVerified: (callback: () => void) => number;
        onBridgeConnect: (callback: () => void) => number;
        notifyReject: () => Promise<void>;
        notifyAccept: () => Promise<void>;
        notifyDone: (proof: any) => Promise<void>;
        notifyError: (error: string) => Promise<void>;
    }>;
}
