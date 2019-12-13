"use strict";
var LeanCrypt;
(function (LeanCrypt) {
    const PBKDF2_ITERATIONS = 100000;
    async function encrypt(data, key) {
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
    LeanCrypt.encrypt = encrypt;
    async function decrypt(data, key) {
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
    LeanCrypt.decrypt = decrypt;
    async function encryptObject(obj, props, key) {
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
        encryptedObject.encrypted = await encrypt(JSON.stringify(encryptedProperties), key);
        return encryptedObject;
    }
    LeanCrypt.encryptObject = encryptObject;
    async function newKey(passphrase) {
        let salt = randomBytes(32);
        return getKey(passphrase, salt);
    }
    LeanCrypt.newKey = newKey;
    async function getKey(passphrase, salt) {
        let saltBytes = (typeof salt == 'string') ? fromBase64String(salt) : salt;
        let keyMaterial = await getKeyMaterial(passphrase);
        let key = await window.crypto.subtle.deriveKey({
            "name": "PBKDF2",
            salt: saltBytes,
            "iterations": PBKDF2_ITERATIONS,
            "hash": "SHA-256"
        }, keyMaterial, { "name": "AES-GCM", "length": 256 }, true, ["encrypt", "decrypt"]);
        return new LeanKey(saltBytes, key);
    }
    LeanCrypt.getKey = getKey;
    class LeanKey {
        constructor(salt, key) {
            this.salt = salt;
            this.key = key;
            this.saltString = toBase64String(salt);
        }
    }
    LeanCrypt.LeanKey = LeanKey;
    class LeanCrypted {
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
    LeanCrypt.LeanCrypted = LeanCrypted;
    class EncryptedProperties {
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
            return new EncryptedProperties(iv, cipherText);
        }
    }
    LeanCrypt.EncryptedProperties = EncryptedProperties;
    async function getKeyMaterial(passphrase) {
        let keyMaterial = window.crypto.subtle.importKey("raw", toUtf8Bytes(passphrase), { name: "PBKDF2" }, // TODO: fix this in typescript definition
        false, ["deriveBits", "deriveKey"]);
        return keyMaterial;
    }
    function randomBytes(numOfBytes) {
        let bytes = new Uint8Array(numOfBytes);
        window.crypto.getRandomValues(bytes);
        return bytes;
    }
    LeanCrypt.randomBytes = randomBytes;
    function toUtf8Bytes(plainText) {
        let enc = new TextEncoder();
        return enc.encode(plainText);
    }
    LeanCrypt.toUtf8Bytes = toUtf8Bytes;
    function fromUtf8Bytes(buffer) {
        let dec = new TextDecoder();
        return dec.decode(buffer);
    }
    LeanCrypt.fromUtf8Bytes = fromUtf8Bytes;
    function toBase64String(buffer) {
        let base64String = btoa(String.fromCharCode(...new Uint8Array(buffer)));
        return base64String;
    }
    LeanCrypt.toBase64String = toBase64String;
    function fromBase64String(base64String) {
        let buffer = Uint8Array.from(atob(base64String), c => c.charCodeAt(0));
        return buffer;
    }
    LeanCrypt.fromBase64String = fromBase64String;
})(LeanCrypt || (LeanCrypt = {}));
