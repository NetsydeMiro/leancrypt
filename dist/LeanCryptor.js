export class Encrypted {
    constructor(salt, iv, cipherText) {
        this.salt = salt;
        this.iv = iv;
        this.cipherText = cipherText;
    }
    toString() {
        return `${toBase64String(this.salt)}:${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`;
    }
    static fromString(encryptedString) {
        let parts = encryptedString.split(':');
        let [salt, iv, cipherText] = parts.map(fromBase64String);
        return new Encrypted(salt, iv, cipherText);
    }
}
export class LeanCrypt {
    // TODO: make all parameters configurable
    constructor() { }
    async encryptObject(obj, props, passphrase) {
        let encryptedObject = {};
        let encryptedProperties = {};
        for (let prop of Object.keys(obj)) {
            if (props.indexOf(prop) >= 0) {
                encryptedProperties[prop] = obj[prop];
            }
            else {
                encryptedObject[prop] = obj[prop];
            }
        }
        encryptedObject.encrypted = await this.encrypt(JSON.stringify(encryptedProperties), passphrase);
        return encryptedObject;
    }
    async encrypt(plainText, passphrase) {
        let utf8Buffer = toUtf8Bytes(plainText);
        let iv = this.randomBytes(32);
        let { salt, key } = await this.getKey(passphrase);
        let cipherText = await window.crypto.subtle.encrypt({
            name: "AES-GCM",
            iv
        }, key, utf8Buffer);
        return new Encrypted(salt, iv, cipherText);
    }
    async decrypt(encrypted, passphrase) {
        let { salt, iv, cipherText } = encrypted;
        let { key } = await this.getKey(passphrase, salt);
        let decrypted = await window.crypto.subtle.decrypt({
            name: "AES-GCM",
            iv: iv
        }, key, cipherText);
        return fromUtf8Bytes(decrypted);
    }
    async getKeyMaterial(passphrase) {
        let keyMaterial = window.crypto.subtle.importKey("raw", toUtf8Bytes(passphrase), { name: "PBKDF2" }, // TODO: fix this in typescript definition
        false, ["deriveBits", "deriveKey"]);
        return keyMaterial;
    }
    randomBytes(numOfBytes) {
        let bytes = new Uint8Array(numOfBytes);
        window.crypto.getRandomValues(bytes);
        return bytes;
    }
    async getKey(passphrase, salt) {
        salt = (salt !== null && salt !== void 0 ? salt : this.randomBytes(32));
        let keyMaterial = await this.getKeyMaterial(passphrase);
        let key = await window.crypto.subtle.deriveKey({
            "name": "PBKDF2",
            salt,
            "iterations": 100000,
            "hash": "SHA-256"
        }, keyMaterial, { "name": "AES-GCM", "length": 256 }, true, ["encrypt", "decrypt"]);
        return { key, salt };
    }
}
function toUtf8Bytes(plainText) {
    let enc = new TextEncoder();
    return enc.encode(plainText);
}
function fromUtf8Bytes(buffer) {
    let dec = new TextDecoder();
    return dec.decode(buffer);
}
function toBase64String(buffer) {
    let base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
    return base64String;
}
function fromBase64String(base64String) {
    let buffer = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
    return buffer;
}
export default LeanCrypt;
