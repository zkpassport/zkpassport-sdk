export declare function generateECDHKeyPair(): Promise<{
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}>;
export declare function getSharedSecret(privateKey: string, publicKey: string): Promise<Uint8Array>;
export declare function encrypt(message: string, sharedSecret: Uint8Array, topic: string): Promise<Uint8Array>;
export declare function decrypt(ciphertext: Uint8Array, sharedSecret: Uint8Array, topic: string): Promise<string>;
