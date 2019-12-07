import { randomBytes, toUtf8Bytes, fromUtf8Bytes, toBase64String, fromBase64String } from './utility.js';
export class LeanCrypt {
    constructor(pbkdf2Iterations = 100000) {
        this.pbkdf2Iterations = pbkdf2Iterations;
    }
    async encrypt(data, key) {
        let dataIsString = false;
        let buffer;
        if (typeof data == 'string') {
            dataIsString = true;
            buffer = toUtf8Bytes(data);
        }
        else
            buffer = data;
        let iv = randomBytes(32);
        let cipherText = await window.crypto.subtle.encrypt({
            name: "AES-GCM",
            iv
        }, key, buffer);
        let leanCrypted = new LeanCrypted(iv, cipherText);
        return dataIsString ? leanCrypted.toString() : leanCrypted;
    }
    async decrypt(data, key) {
        let dataIsString = false;
        let leanCrypted;
        if (typeof data == 'string') {
            dataIsString = true;
            leanCrypted = LeanCrypted.fromString(data);
        }
        else
            leanCrypted = data;
        let { iv, cipherText } = leanCrypted;
        let decrypted = await window.crypto.subtle.decrypt({
            name: "AES-GCM",
            iv
        }, key, cipherText);
        return dataIsString ? fromUtf8Bytes(decrypted) : decrypted;
    }
    async newKey(passphrase) {
        let salt = randomBytes(32);
        return this.getKey(passphrase, salt);
    }
    async getKey(passphrase, salt) {
        let saltBytes = (typeof salt == 'string') ? fromBase64String(salt) : salt;
        let keyMaterial = await getKeyMaterial(passphrase);
        let key = await window.crypto.subtle.deriveKey({
            "name": "PBKDF2",
            salt: saltBytes,
            "iterations": this.pbkdf2Iterations,
            "hash": "SHA-256"
        }, keyMaterial, { "name": "AES-GCM", "length": 256 }, true, ["encrypt", "decrypt"]);
        return new LeanKey(saltBytes, key);
    }
}
export class LeanKey {
    constructor(salt, key) {
        this.salt = salt;
        this.key = key;
        this.saltString = toBase64String(salt);
    }
}
export class LeanCrypted {
    constructor(iv, cipherText) {
        this.iv = iv;
        this.cipherText = cipherText;
    }
    toString() {
        return `${toBase64String(this.iv)}:${toBase64String(this.cipherText)}`;
    }
    static fromString(encryptedString) {
        let parts = encryptedString.split(':');
        let [iv, cipherText] = parts.map(fromBase64String);
        return new LeanCrypted(iv, cipherText);
    }
}
async function getKeyMaterial(passphrase) {
    let keyMaterial = window.crypto.subtle.importKey("raw", toUtf8Bytes(passphrase), { name: "PBKDF2" }, // TODO: fix this in typescript definition
    false, ["deriveBits", "deriveKey"]);
    return keyMaterial;
}
export default LeanCrypt;
