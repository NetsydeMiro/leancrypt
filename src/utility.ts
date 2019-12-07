export class SaltedHash {
    constructor(
        public salt: ArrayBuffer,
        public hash: ArrayBuffer
    ) { 
        this.saltString = toBase64String(salt)
        this.hashString = toBase64String(hash)
    }

    public saltString: string
    public hashString: string
}

export async function hash(passphrase: string, salt?: string): Promise<SaltedHash> {
    let saltBytes = salt ? fromBase64String(salt) : randomBytes(32)
    let passBytes = toUtf8Bytes(passphrase)

    let saltedValue = new Uint8Array(saltBytes.length + passBytes.length)
    saltedValue.set(saltBytes)
    saltedValue.set(passBytes, saltBytes.length)

    let hash = await crypto.subtle.digest('SHA-512', saltedValue)

    return new SaltedHash(saltBytes, hash)
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
