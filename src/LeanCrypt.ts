namespace LeanCrypt {

    const PBKDF2_ITERATIONS = 100_000

    export async function encrypt(plainText: string, key: CryptoKey): Promise<string>
    export async function encrypt(buffer: ArrayBuffer, key: CryptoKey): Promise<LeanCrypted>

    export async function encrypt(data: string | ArrayBuffer, key: CryptoKey): Promise<string | LeanCrypted> {
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

    export async function decrypt(encrypted: string, key: CryptoKey): Promise<string>
    export async function decrypt(leanCrypted: LeanCrypted, key: CryptoKey): Promise<ArrayBuffer>

    export async function decrypt(data: string | LeanCrypted, key: CryptoKey): Promise<string | ArrayBuffer> {
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

    export async function encryptObject<T, K extends keyof T>(obj: T, props: Array<K>, key: CryptoKey): Promise<EncryptedObject<T, K>> {
        let encryptedObject = {} as any
        let encryptedProperties = {} as any

        for (let prop of Object.keys(obj)) {
            if (props.indexOf(prop as any) >= 0) {
                encryptedProperties[prop] = (obj as any)[prop]
            }
            else {
                encryptedObject[prop] = (obj as any)[prop]
            }
        }
        encryptedObject.encrypted = await encrypt(JSON.stringify(encryptedProperties), key)

        return encryptedObject
    }

    export async function newKey(passphrase: string): Promise<LeanKey> {
        let salt = randomBytes(32)

        return getKey(passphrase, salt)
    }

    export async function getKey(passphrase: string, salt: string | Uint8Array): Promise<LeanKey> {
        let saltBytes: Uint8Array = (typeof salt == 'string') ? fromBase64String(salt) : salt

        let keyMaterial = await getKeyMaterial(passphrase)

        let key = await window.crypto.subtle.deriveKey(
            {
                "name": "PBKDF2",
                salt: saltBytes,
                "iterations": PBKDF2_ITERATIONS,
                "hash": "SHA-256"
            },
            keyMaterial,
            { "name": "AES-GCM", "length": 256 },
            true,
            ["encrypt", "decrypt"]
        )
        return new LeanKey(saltBytes, key)
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

    export class EncryptedProperties {
        constructor(
            public iv: Uint8Array,
            public cipherText: ArrayBuffer,
        ) { }

        toString(): string {
            return `${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`
        }

        static fromString(encryptedString: string): EncryptedProperties {
            let parts = encryptedString.split(':')

            let [iv, cipherText] = parts.map(fromBase64String)

            return new EncryptedProperties(iv, cipherText)
        }
    }

    export type EncryptedObject<T, K extends keyof T> = Pick<T, Exclude<keyof T, K>> & {
        encrypted: EncryptedProperties
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

    export function randomBytes(numOfBytes: number): Uint8Array {
        let bytes = new Uint8Array(numOfBytes)
        window.crypto.getRandomValues(bytes)
        return bytes
    }

    export function toUtf8Bytes(plainText: string): Uint8Array {
        let enc = new TextEncoder()
        return enc.encode(plainText)
    }

    export function fromUtf8Bytes(buffer: ArrayBuffer): string {
        let dec = new TextDecoder()
        return dec.decode(buffer)
    }

    export function toBase64String(buffer: ArrayBuffer): string {
        let base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64String
    }

    export function fromBase64String(base64String: string): Uint8Array {
        let buffer = Uint8Array.from(atob(base64String), c => c.charCodeAt(0))
        return buffer
    }
}
