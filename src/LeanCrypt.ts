export class LeanCrypt {
    constructor(private pbkdf2Iterations: number = 100_000) { }

    // TODO: enable encrypting via key 
    async encrypt(plainText: string, passphrase: string): Promise<string> 
    async encrypt(buffer: ArrayBuffer, passphrase: string): Promise<LeanCrypted> 

    async encrypt(data: string | ArrayBuffer, passphrase: string): Promise<string | LeanCrypted> {
        let dataIsString = false
        let buffer: ArrayBuffer

        if (typeof data == 'string') { 
            dataIsString = true
            buffer = toUtf8Bytes(data) 
        }
        else buffer = data

        let iv = this.randomBytes(32)
        let { salt, key } = await this.getKey(passphrase)

        let cipherText = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            buffer
        )
        let leanCrypted = new LeanCrypted(salt, iv, cipherText)

        return dataIsString ? leanCrypted.toString() : leanCrypted
    }

    async decrypt(encrypted: string, passphrase: string): Promise<string> 
    async decrypt(leanCrypted: LeanCrypted, passphrase: string): Promise<ArrayBuffer> 

    async decrypt(data: string | LeanCrypted, passphrase: string): Promise<string | ArrayBuffer> {
        let dataIsString = false
        let leanCrypted: LeanCrypted

        if (typeof data == 'string') {
            dataIsString = true
            leanCrypted = LeanCrypted.fromString(data)
        }
        else leanCrypted = data

        let { salt, iv, cipherText } = leanCrypted

        let { key } = await this.getKey(passphrase, salt)

        let decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            cipherText
        )
        return dataIsString ? fromUtf8Bytes(decrypted) : decrypted
    }

    private async getKeyMaterial(passphrase: string): Promise<CryptoKey> {
        let keyMaterial = window.crypto.subtle.importKey(
            "raw",
            toUtf8Bytes(passphrase),
            { name: "PBKDF2" } as any,  // TODO: fix this in typescript definition
            false,
            ["deriveBits", "deriveKey"]
        )
        return keyMaterial
    }

    private randomBytes(numOfBytes: number): Uint8Array {
        let bytes = new Uint8Array(numOfBytes)
        window.crypto.getRandomValues(bytes)
        return bytes
    }

    private async getKey(passphrase: string, salt?: Uint8Array): Promise<SaltedKey> {
        salt = salt ?? this.randomBytes(32)

        let keyMaterial = await this.getKeyMaterial(passphrase)

        let key = await window.crypto.subtle.deriveKey(
            {
                "name": "PBKDF2",
                salt,
                "iterations": this.pbkdf2Iterations,
                "hash": "SHA-256"
            },
            keyMaterial,
            { "name": "AES-GCM", "length": 256 },
            true,
            ["encrypt", "decrypt"]
        )
        return { key, salt }
    }
}

interface SaltedKey {
    key: CryptoKey
    salt: Uint8Array
}

class LeanCrypted {
    constructor(
        public salt: Uint8Array, 
        public iv: Uint8Array,
        public cipherText: ArrayBuffer, 
    ) { }

    toString(): string {
        return `${toBase64String(this.salt)}:${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`
    }

    static fromString(encryptedString: string): LeanCrypted {
        let parts = encryptedString.split(':')

        let [salt, iv, cipherText] = parts.map(fromBase64String)

        return new LeanCrypted(salt, iv, cipherText)
    }
}

function toUtf8Bytes(plainText: string): Uint8Array {
    let enc = new TextEncoder()
    return enc.encode(plainText)
}

function fromUtf8Bytes(buffer: ArrayBuffer): string {
    let dec = new TextDecoder()
    return dec.decode(buffer)
}

function toBase64String(buffer: ArrayBuffer): string {
    let base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64String
}

function fromBase64String(base64String: string): Uint8Array {
    let buffer = Uint8Array.from(atob(base64String), c => c.charCodeAt(0))
    return buffer
}

export default LeanCrypt