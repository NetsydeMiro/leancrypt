import { randomBytes, toUtf8Bytes, fromUtf8Bytes, toBase64String, fromBase64String } from './utility.js'

export class LeanCrypt {
    constructor(private pbkdf2Iterations: number = 100_000) { }

    // TODO: enable encrypting via key 
    async encrypt(plainText: string, key: CryptoKey): Promise<string> 
    async encrypt(buffer: ArrayBuffer, key: CryptoKey): Promise<LeanCrypted> 

    async encrypt(data: string | ArrayBuffer, key: CryptoKey): Promise<string | LeanCrypted> {
        let dataIsString = false
        let buffer: ArrayBuffer

        if (typeof data == 'string') { 
            dataIsString = true
            buffer = toUtf8Bytes(data) 
        }
        else buffer = data

        let iv = randomBytes(32)

        let cipherText = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            buffer
        )
        let leanCrypted = new LeanCrypted(iv, cipherText)

        return dataIsString ? leanCrypted.toString() : leanCrypted
    }

    async decrypt(encrypted: string, key: CryptoKey): Promise<string> 
    async decrypt(leanCrypted: LeanCrypted, key: CryptoKey): Promise<ArrayBuffer> 

    async decrypt(data: string | LeanCrypted, key: CryptoKey): Promise<string | ArrayBuffer> {
        let dataIsString = false
        let leanCrypted: LeanCrypted

        if (typeof data == 'string') {
            dataIsString = true
            leanCrypted = LeanCrypted.fromString(data)
        }
        else leanCrypted = data

        let { iv, cipherText } = leanCrypted

        let decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            cipherText
        )
        return dataIsString ? fromUtf8Bytes(decrypted) : decrypted
    }

    async newKey(passphrase: string): Promise<LeanKey> {
        let salt = randomBytes(32)

        return this.getKey(passphrase, salt)
    }

    async getKey(passphrase: string, salt: string | Uint8Array): Promise<LeanKey> {
        let saltBytes: Uint8Array = (typeof salt == 'string') ? fromBase64String(salt) : salt

        let keyMaterial = await getKeyMaterial(passphrase)

        let key = await window.crypto.subtle.deriveKey(
            {
                "name": "PBKDF2",
                salt: saltBytes,
                "iterations": this.pbkdf2Iterations,
                "hash": "SHA-256"
            },
            keyMaterial,
            { "name": "AES-GCM", "length": 256 },
            true,
            ["encrypt", "decrypt"]
        )
        return new LeanKey(saltBytes, key)
    }
}

export class LeanKey {
    constructor(
        public salt: Uint8Array,
        public key: CryptoKey
    ) {
        this.saltString = toBase64String(salt)
    }

    public saltString: string
}

export class LeanCrypted {
    constructor(
        public iv: Uint8Array,
        public cipherText: ArrayBuffer, 
    ) { }

    toString(): string {
        return `${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`
    }

    static fromString(encryptedString: string): LeanCrypted {
        let parts = encryptedString.split(':')

        let [iv, cipherText] = parts.map(fromBase64String)

        return new LeanCrypted(iv, cipherText)
    }
}

async function getKeyMaterial(passphrase: string): Promise<CryptoKey> {
    let keyMaterial = window.crypto.subtle.importKey(
        "raw",
        toUtf8Bytes(passphrase),
        { name: "PBKDF2" } as any,  // TODO: fix this in typescript definition
        false,
        ["deriveBits", "deriveKey"]
    )
    return keyMaterial
}

export default LeanCrypt