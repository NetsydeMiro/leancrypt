export class Encrypted {
    constructor(
        public salt: Uint8Array, 
        public iv: Uint8Array,
        public cipherText: ArrayBuffer, 
    ) { }

    toString(): string {
        return `${toBase64String(this.salt)}:${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`
    }

    static fromString(encryptedString: string): Encrypted {
        let parts = encryptedString.split(':')

        let [salt, iv, cipherText] = parts.map(fromBase64String)

        return new Encrypted(salt, iv, cipherText)
    }
}

type EncryptedObject<T, K extends keyof T> = Pick<T, Exclude<keyof T, K>> & {
    encrypted: Encrypted
}

export class LeanCrypt {
    // TODO: make all parameters configurable
    constructor() { }

    async encryptObject<T, K extends keyof T>(obj: T, props: Array<K>, passphrase: string): Promise<EncryptedObject<T, K>> {
        let encryptedObject = {} as any
        let encryptedProperties = {}  as any

        for(let prop of Object.keys(obj)) {
            if (props.indexOf(prop as any) >= 0) {
                encryptedProperties[prop] = (obj as any)[prop] 
            }
            else {
                encryptedObject[prop] = (obj as any)[prop] 
            }
        }
        encryptedObject.encrypted = await this.encrypt(JSON.stringify(encryptedProperties), passphrase)
        
        return encryptedObject
    }

    async encrypt(plainText: string, passphrase: string): Promise<Encrypted> {
        let utf8Buffer = toUtf8Bytes(plainText)

        let iv = this.randomBytes(32)
        let { salt, key } = await this.getKey(passphrase)

        let cipherText = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv
            },
            key,
            utf8Buffer
        )
        return new Encrypted(salt, iv, cipherText)
    }

    async decrypt(encrypted: Encrypted, passphrase: string): Promise<string> {
        let { salt, iv, cipherText } = encrypted

        let { key } = await this.getKey(passphrase, salt)

        let decrypted = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            cipherText
        )
        return fromUtf8Bytes(decrypted)
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
                "iterations": 100000,
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