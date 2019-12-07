export class SaltedHash {
    constructor(salt, hash) {
        this.salt = salt;
        this.hash = hash;
        this.saltString = toBase64String(salt);
        this.hashString = toBase64String(hash);
    }
}
export async function hash(passphrase, salt) {
    let saltBytes = salt ? fromBase64String(salt) : randomBytes(32);
    let passBytes = toUtf8Bytes(passphrase);
    let saltedValue = new Uint8Array(saltBytes.length + passBytes.length);
    saltedValue.set(saltBytes);
    saltedValue.set(passBytes, saltBytes.length);
    let hash = await crypto.subtle.digest('SHA-512', saltedValue);
    return new SaltedHash(saltBytes, hash);
}
export function randomBytes(numOfBytes) {
    let bytes = new Uint8Array(numOfBytes);
    window.crypto.getRandomValues(bytes);
    return bytes;
}
export function toUtf8Bytes(plainText) {
    let enc = new TextEncoder();
    return enc.encode(plainText);
}
export function fromUtf8Bytes(buffer) {
    let dec = new TextDecoder();
    return dec.decode(buffer);
}
export function toBase64String(buffer) {
    let base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64String;
}
export function fromBase64String(base64String) {
    let buffer = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
    return buffer;
}
