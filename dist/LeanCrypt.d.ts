declare namespace LeanCrypt {
    function encrypt(plainText: string, key: CryptoKey): Promise<string>;
    function encrypt(buffer: ArrayBuffer, key: CryptoKey): Promise<LeanCrypted>;
    function decrypt(encrypted: string, key: CryptoKey): Promise<string>;
    function decrypt(leanCrypted: LeanCrypted, key: CryptoKey): Promise<ArrayBuffer>;
    function encryptObject<T, K extends keyof T>(obj: T, props: Array<K>, key: CryptoKey): Promise<EncryptedObject<T, K>>;
    function newKey(passphrase: string): Promise<LeanKey>;
    function getKey(passphrase: string, salt: string | Uint8Array): Promise<LeanKey>;
    class LeanKey {
        salt: Uint8Array;
        key: CryptoKey;
        constructor(salt: Uint8Array, key: CryptoKey);
        saltString: string;
    }
    class LeanCrypted {
        iv: Uint8Array;
        cipherText: ArrayBuffer;
        constructor(iv: Uint8Array, cipherText: ArrayBuffer);
        toString(): string;
        static fromString(encryptedString: string): LeanCrypted;
    }
    class EncryptedProperties {
        iv: Uint8Array;
        cipherText: ArrayBuffer;
        constructor(iv: Uint8Array, cipherText: ArrayBuffer);
        toString(): string;
        static fromString(encryptedString: string): EncryptedProperties;
    }
    type EncryptedObject<T, K extends keyof T> = Pick<T, Exclude<keyof T, K>> & {
        encrypted: EncryptedProperties;
    };
    function randomBytes(numOfBytes: number): Uint8Array;
    function toUtf8Bytes(plainText: string): Uint8Array;
    function fromUtf8Bytes(buffer: ArrayBuffer): string;
    function toBase64String(buffer: ArrayBuffer): string;
    function fromBase64String(base64String: string): Uint8Array;
}
